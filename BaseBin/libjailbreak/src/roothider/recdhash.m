#include <libgen.h>
#include <mach-o/dyld.h>
#include <stddef.h>

#include <choma/Fat.h>
#include <choma/MachO.h>
#include <choma/Host.h>
#include <choma/MachOByteOrder.h>
#include <choma/CodeDirectory.h>

#include "../libjailbreak.h"
#include "common.h"
#include "log.h"
#include "signature_policy.h"
#include "../codesign.h"
#include "../signatures.h"

_Static_assert(ROOTHIDE_SIGNATURE_FLAG_ADHOC == CS_ADHOC, "signature flag mismatch");

extern MachO* fat_find_preferred_slice(Fat* fat);

extern CS_DecodedBlob *csd_superblob_find_best_code_directory(CS_DecodedSuperBlob *decodedSuperblob);
extern bool code_directory_calculate_page_hash(CS_CodeDirectory *codeDir, MachO *macho, int slot, uint8_t *pageHashOut);

/* 
if here are any unclosed file descriptors before the Dopamine process ends, 
	the "attempt to map verified executable page" panic may occur.
*/
Fat* fat_init_for_writing(const char *filePath)
{
	//make sure the file already exists, otherwise choma will create a new file
	if(access(filePath, W_OK) != 0) {
		JBLogError("Error: file is not writable: %s\n", filePath);
		return NULL;
	}

    MemoryStream *stream = file_stream_init_from_path(filePath, 0, FILE_STREAM_SIZE_AUTO, FILE_STREAM_FLAG_WRITABLE);
    if(!stream) return NULL;

	Fat *fat = fat_init_from_memory_stream(stream);
	if (!fat) memory_stream_free(stream);
	return fat;
}

static bool roothide_is_code_directory_slot(uint32_t type)
{
	return type == CSSLOT_CODEDIRECTORY
		|| (type >= CSSLOT_ALTERNATE_CODEDIRECTORIES && type < CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT);
}

static bool roothide_read_code_directory(CS_DecodedBlob *blob, bool usesSPTM,
	CS_CodeDirectory *directoryOut, uint32_t *flagsOut)
{
	if (!blob) return false;
	size_t size = csd_blob_get_size(blob);
	if (size < offsetof(CS_CodeDirectory, scatterOffset)
		|| size > ROOTHIDE_SIGNATURE_MAX_DIRECTORY_SIZE) return false;
	uint8_t *bytes = malloc(size);
	if (!bytes) return false;
	bool valid = csd_blob_read(blob, 0, size, bytes) == 0
		&& roothide_signature_normalized_flags(bytes, size, usesSPTM, flagsOut);
	CS_CodeDirectory directory = {0};
	if (valid) {
		memcpy(&directory, bytes, size < sizeof(directory) ? size : sizeof(directory));
		CODE_DIRECTORY_APPLY_BYTE_ORDER(&directory, BIG_TO_HOST_APPLIER);
		bool hashShapeValid = (directory.hashType == CS_HASHTYPE_SHA160_160 && directory.hashSize == 20)
			|| (directory.hashType == CS_HASHTYPE_SHA256_256 && directory.hashSize == 32)
			|| (directory.hashType == CS_HASHTYPE_SHA256_160 && directory.hashSize == 20)
			|| (directory.hashType == CS_HASHTYPE_SHA384_384 && directory.hashSize == 48);
		valid = hashShapeValid && directory.nCodeSlots > 0
			&& directory.pageSize <= 16 && (directory.pageSize != 0 || directory.nCodeSlots == 1)
			&& directory.hashOffset <= size
			&& (uint64_t)directory.nCodeSlots * directory.hashSize <= size - directory.hashOffset
			&& (uint64_t)directory.nSpecialSlots * directory.hashSize <= directory.hashOffset;
	}
	free(bytes);
	if (valid) *directoryOut = directory;
	return valid;
}

int roothide_code_directories_need_normalization(CS_DecodedSuperBlob *superblob, bool usesSPTM)
{
	if (!superblob) return -1;
	bool needsNormalization = false;
	uint32_t seenSlots = 0;
	for (CS_DecodedBlob *blob = superblob->firstBlob; blob; blob = blob->next) {
		if (!roothide_is_code_directory_slot(blob->type)) continue;
		unsigned slot = blob->type == CSSLOT_CODEDIRECTORY ? 0 : 1 + blob->type - CSSLOT_ALTERNATE_CODEDIRECTORIES;
		if (seenSlots & (1u << slot)) return -1;
		seenSlots |= 1u << slot;
		CS_CodeDirectory directory;
		uint32_t flags;
		if (!roothide_read_code_directory(blob, usesSPTM, &directory, &flags)) return -1;
		if (flags != directory.flags) needsNormalization = true;
	}
	return seenSlots ? needsNormalization : -1;
}

int calc_cdhash(uint8_t *cdBlob, size_t cdBlobSize, uint8_t hashtype, void *cdhashOut)
{
    // Longest possible buffer, will cut it off at the end as cdhash size is fixed
    uint8_t cdhash[CC_SHA384_DIGEST_LENGTH];

    JBLogDebug("head=%llx  %lx\n", *(uint64_t*)cdBlob, cdBlobSize);

    switch (hashtype) {
		case CS_HASHTYPE_SHA160_160: {
			CC_SHA1(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}
		
		case CS_HASHTYPE_SHA256_256:
		case CS_HASHTYPE_SHA256_160: {
			CC_SHA256(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

		case CS_HASHTYPE_SHA384_384: {
			CC_SHA384(cdBlob, (CC_LONG)cdBlobSize, cdhash);
			break;
		}

        default:
        return -1;
	}

    memcpy(cdhashOut, cdhash, CS_CDHASH_LEN);
    return 0;
}

MachO* fat_find_slice_by_offset(Fat* fat, uint64_t offset)
{
	__block MachO* result = NULL;
	fat_enumerate_slices(fat, ^(MachO *macho, bool *stop) {
		if(macho->archDescriptor.offset == offset) {
			result = macho;
			*stop = true;
		}
	});
	return result;
}

int ensure_randomized_cdhash(const char* inputPath, void* cdhashOut)
{
	return ensure_randomized_cdhash_for_slice(inputPath, -1, cdhashOut);
}

/* on ios16(+?)
1: if an executable has process(es) running it, after opening it with open(O_RDWR), 
		it can no longer be executed (EBADMACHO) until the previous process(es) exits.
2: if an executable is opened with O_RDWR, 
	it cannot be executed until the file descriptor is closed.
3: `open(O_RDWR)` on certain binaries(e.g., WebContent) may cause deadlock (krwlock for writing)
	while `read`/`posix_spawn` happen to be running on the binary.
*/
int ensure_randomized_cdhash_for_slice(const char* inputPath, uint64_t offset, void* cdhashOut)
{
	if (!inputPath || !cdhashOut) return -1;
	JBLogDebug("ensure_randomized_cdhash_for_slice(slice=%llx): %s\n", offset, inputPath);

    Fat* fat = fat_init_for_writing(inputPath);
    if (!fat) {
		JBLogError("Error: failed to init fat: %s\n", inputPath);
		return -1;
	}

    MachO *macho = (offset == UINT64_MAX) ? fat_find_preferred_slice(fat) : fat_find_slice_by_offset(fat, offset);
	if(!macho) {
		JBLogError("Error: failed to find preferred slice: %s\n", inputPath);
		fat_free(fat);
		return -1;
	}

	__block int foundCount = 0;
    __block uint64_t textsegoffset = 0;
    __block uint64_t firstsectoffset = 0;
	__block struct section_64 firstsection={0};
    __block struct segment_command_64 textsegment={0};
    __block struct linkedit_data_command linkedit={0};

    macho_enumerate_load_commands(macho, ^(struct load_command loadCommand, uint64_t offset, void *cmd, bool *stop) {
		bool foundOne = false;
		if (loadCommand.cmd == LC_SEGMENT_64) {
			struct segment_command_64 *segmentCommand = ((struct segment_command_64 *)cmd);

			if (strcmp(segmentCommand->segname, "__TEXT") != 0) return;

			textsegoffset = offset;
			textsegment = *segmentCommand;

			if(segmentCommand->nsects==0) {
				*stop=true;
				return;
			}

			firstsectoffset = textsegoffset + sizeof(*segmentCommand);
			firstsection = *(struct section_64*)((uint64_t)segmentCommand + sizeof(*segmentCommand));
			if (strcmp(firstsection.segname, "__TEXT") != 0) {
				*stop=true;
				return;
			}
			
			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
		if (loadCommand.cmd == LC_CODE_SIGNATURE) {
			struct linkedit_data_command *csLoadCommand = ((struct linkedit_data_command *)cmd);
			JBLogDebug("LC_CODE_SIGNATURE: %x\n", csLoadCommand->dataoff);

			linkedit = *csLoadCommand;

			*stop = foundOne;
			foundOne = true;
			foundCount++;
		}
    });

    if(foundCount < 2) {
		JBLogError("Error: failed to parse macho file: %s\n", inputPath);
		fat_free(fat);
		return -1;
	}

    uint64_t* rd = (uint64_t*)&(textsegment.segname[sizeof(textsegment.segname)-sizeof(uint64_t)]); //Modifying this will cause some apps to crash
    uint64_t* rd2 = (uint64_t*)&(firstsection.segname[sizeof(firstsection.segname)-sizeof(uint64_t)]);
    JBLogDebug("__TEXT: %llx,%llx, %016llX %016llX\n", textsegoffset, textsegment.fileoff, *rd, *rd2);

    CS_SuperBlob *superblob = macho_read_code_signature(macho);
    if (!superblob) {
        JBLogError("Error: failed to read code signature: %s\n", inputPath);
		fat_free(fat);
        return -1;
    }

    JBLogDebug("super blob: %x %x %d\n", superblob->magic, BIG_TO_HOST(superblob->length), BIG_TO_HOST(superblob->count));

    CS_DecodedSuperBlob *decodedSuperblob = csd_superblob_decode(superblob);
	if(!decodedSuperblob || !csd_superblob_is_adhoc_signed(decodedSuperblob)) {
		JBLogError("Error: failed to decode superblob: %s\n", inputPath);
		if (decodedSuperblob) csd_superblob_free(decodedSuperblob);
		free(superblob);
		fat_free(fat);
		return -1;
	}

    int retval=-1;
	do
	{
		CS_DecodedBlob *bestCDBlob = csd_superblob_find_best_code_directory(decodedSuperblob);
		if(!bestCDBlob) {
			JBLogError("Error: failed to find best code directory: %s\n", inputPath);
			break;
		}
		bool usesSPTM = ksymbol(SPTMArgs) != 0;
		// Validate every directory before changing the executable's jbrand.
		if (roothide_code_directories_need_normalization(decodedSuperblob, usesSPTM) < 0) {
			JBLogError("Error: invalid code directory metadata: %s", inputPath);
			break;
		}

		bool alreadyPatched = (*rd2 == jbinfo(jbrand));
		if (!alreadyPatched) {
			if(isRemovableBundlePath(inputPath))
			{
				if(!hasTrollstoreLiteMarker(inputPath)) {
					// ignore adhoc signed apps(removable system apps or other stuffs) which is not installed via tslite
					JBLogDebug("ignoring addhoc signed app: %s\n", inputPath);
					break;
				}
			}
	
			*rd2 = jbinfo(jbrand);

			JBLogDebug("randomize cdhash with %016llX: %s\n", *rd2, inputPath);
		
			if(memory_stream_write(fat->stream, macho->archDescriptor.offset + firstsectoffset, sizeof(firstsection), &firstsection) != 0) {
				JBLogError("Error: failed to write macho file: %s\n", inputPath);
				break;
			}
		} else {
			JBLogDebug("macho already patched, validating code directories: %s\n", inputPath);
		}

		bool codeDirectoryUpdateFailed = false;
		for (uint32_t i = 0; i < BIG_TO_HOST(superblob->count); i++) {
			CS_BlobIndex curIndex = superblob->index[i];
			BLOB_INDEX_APPLY_BYTE_ORDER(&curIndex, BIG_TO_HOST_APPLIER);
			//JBLogDebug("decoding %u (type: %x, offset: 0x%x)\n", i, curIndex.type, curIndex.offset);

			bool isCodeDirectory = roothide_is_code_directory_slot(curIndex.type);
			if(isCodeDirectory)
			{
				CS_DecodedBlob *codeDirectoryBlob = csd_superblob_find_blob(decodedSuperblob, curIndex.type, NULL);
				CS_CodeDirectory codeDir;
				uint32_t normalizedFlags;
				if (!roothide_read_code_directory(codeDirectoryBlob, usesSPTM, &codeDir, &normalizedFlags)) {
					JBLogError("Error: failed to read code directory type %x: %s\n", curIndex.type, inputPath);
					codeDirectoryUpdateFailed = true;
					break;
				}

				if (normalizedFlags != codeDir.flags) {
					uint32_t encodedFlags = HOST_TO_BIG(normalizedFlags);
					if (memory_stream_write(fat->stream, macho->archDescriptor.offset + linkedit.dataoff
						+ curIndex.offset + offsetof(CS_CodeDirectory, flags), sizeof(encodedFlags), &encodedFlags) != 0) {
						JBLogError("Error: failed to normalize code directory flags: %s", inputPath);
						codeDirectoryUpdateFailed = true;
						break;
					}
				}
				uint8_t pageHash[CC_SHA384_DIGEST_LENGTH];
				if(!code_directory_calculate_page_hash(&codeDir, macho, 0, pageHash)) {
					JBLogError("Error: failed to calculate page hash for code directory type %x: %s\n", curIndex.type, inputPath);
					codeDirectoryUpdateFailed = true;
					break;
				}

				if(0 != memory_stream_write(fat->stream, macho->archDescriptor.offset + linkedit.dataoff + curIndex.offset + codeDir.hashOffset, codeDir.hashSize, pageHash)) {
					JBLogError("Error: failed to write page hash: %s\n", inputPath);
					codeDirectoryUpdateFailed = true;
					break;
				}

				if (curIndex.type != bestCDBlob->type) continue;

				void* newCDBlob = malloc(codeDir.length);
				if (!newCDBlob) {
					codeDirectoryUpdateFailed = true;
					break;
				}
				if(memory_stream_read(fat->stream, macho->archDescriptor.offset + linkedit.dataoff + curIndex.offset, codeDir.length, newCDBlob) == 0)
				{
					retval = calc_cdhash(newCDBlob, codeDir.length, csd_code_directory_get_hash_type(bestCDBlob), cdhashOut);
					if(retval != 0) {
						JBLogError("Error: failed to calculate cdhash: %s\n", inputPath);
					}
				}
				else
				{
					JBLogError("Error: failed to read new code directory: %s\n", inputPath);
				}

				free(newCDBlob);
			}
		}
		if (codeDirectoryUpdateFailed) retval = -1;

	} while(0);

	csd_superblob_free(decodedSuperblob);

	free(superblob);

	fat_free(fat); //will release MemoryStream and MachO(s)

	return retval;
}

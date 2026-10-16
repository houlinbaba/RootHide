#pragma once
#import <UIKit/UIKit.h>

// UITableView inserts/reorders reusable cells internally. A glass sibling of
// those cells can end up above them and blur their text. Its backgroundView
// stays behind cells, headers and footers throughout scrolling and reuse.
static inline void DOPlaceSectionGlass(UITableView *tableView, UIView *glass, CGRect sectionRect)
{
    UIView *background = tableView.backgroundView;
    if (!background) {
        background = [[UIView alloc] initWithFrame:tableView.bounds];
        background.backgroundColor = UIColor.clearColor;
        background.opaque = NO;
        background.userInteractionEnabled = NO;
        tableView.backgroundView = background;
    }
    if (glass.superview != background) [background addSubview:glass];
    // Convert from scrolling content coordinates into UITableView's managed
    // background coordinates; do not assume a zero bounds origin while scrolling.
    CGRect frame = [tableView convertRect:CGRectInset(sectionRect, 1.0, 0.5) toView:background];
    if (!CGRectEqualToRect(glass.frame, frame)) glass.frame = frame;
}

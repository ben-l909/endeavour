#import <Foundation/Foundation.h>

@protocol Runnable <NSObject>
- (void)run;
@optional
- (double)speed;
@end

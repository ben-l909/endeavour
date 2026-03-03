#import <Foundation/Foundation.h>
#import "Runnable.h"

@interface Animal : NSObject <Runnable>
@property (nonatomic, copy) NSString *name;
@property (nonatomic, assign) NSInteger age;
- (instancetype)initWithName:(NSString *)name age:(NSInteger)age;
- (NSString *)describe;
@end

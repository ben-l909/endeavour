#import "Animal.h"

@interface Dog : Animal
@property (nonatomic, copy) NSString *breed;
- (instancetype)initWithName:(NSString *)name age:(NSInteger)age breed:(NSString *)breed;
- (void)bark;
@end

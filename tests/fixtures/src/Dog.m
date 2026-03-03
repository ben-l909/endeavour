#import "Dog.h"

@implementation Dog

- (instancetype)initWithName:(NSString *)name age:(NSInteger)age breed:(NSString *)breed {
    self = [super initWithName:name age:age];
    if (self) {
        _breed = [breed copy];
    }
    return self;
}

- (void)bark {
    NSLog(@"Woof! I am %@, a %@", self.name, _breed);
}

- (void)run {
    NSLog(@"%@ runs fast!", self.name);
}

- (double)speed {
    return 8.0;
}

@end

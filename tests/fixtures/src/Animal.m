#import "Animal.h"

@implementation Animal

- (instancetype)initWithName:(NSString *)name age:(NSInteger)age {
    self = [super init];
    if (self) {
        _name = [name copy];
        _age = age;
    }
    return self;
}

- (NSString *)describe {
    return [NSString stringWithFormat:@"%@ (age %ld)", _name, (long)_age];
}

- (void)run {
    NSLog(@"%@ is running", _name);
}

- (double)speed {
    return 3.5;
}

@end

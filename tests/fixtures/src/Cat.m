#import "Cat.h"

@implementation Cat

- (void)purr {
    NSLog(@"%@ purrs", self.name);
}

- (void)run {
    NSLog(@"%@ slinks away", self.name);
}

@end

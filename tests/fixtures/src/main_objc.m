#import <Foundation/Foundation.h>
#import "Dog.h"
#import "Cat.h"

int main(void) {
    @autoreleasepool {
        Dog *d = [[Dog alloc] initWithName:@"Rex" age:3 breed:@"Labrador"];
        Cat *c = [[Cat alloc] initWithName:@"Whiskers" age:5];
        [d bark];
        [c purr];
        NSLog(@"%@", [d describe]);
    }
    return 0;
}

#include<iostream>
#include<memory>

#include <unistd.h>
#include <string.h>
#include <stdio.h>

using namespace std;


class A {
public:
    int num;

    A(int n) {
        cout << "asdffffffff\n";
        num = n;
    }
    ~A() {
        cout << "fdsgsdgfds\n";
    }
};

A operator|(A a, A b) {
    cout << a.num << " " << b.num << endl;
    return a;
}

int main() {
    A a(1), b(2), c(2132);
    a | b | c;


}

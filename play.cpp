#include<iostream>
#include<memory>
using namespace std;


class A {
public:
    int num;

    A(int n) {
        cout << "fuck\n";
        num = n;
    }
    ~A() {
        cout << "shit\n";
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

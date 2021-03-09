#include <memory>

struct foo{
	int x;
};

int main(int argc, char** argv){
	std::shared_ptr<foo> fooptr;
	return 0;
}

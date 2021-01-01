#include <boost/smart_ptr.hpp>

struct foo{
	int x;
};

int main(int argc, char** argv){
	boost::shared_ptr<foo> fooptr;
	return 0;
}

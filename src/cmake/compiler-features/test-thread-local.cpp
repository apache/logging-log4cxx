#include <string>

std::string& getCurrentThreadVar()
{
	thread_local std::string thread_id_string;
    return thread_id_string;
}

int main(){
	getCurrentThreadVar() = "name";
}

#include <iostream>

void remote_function(int i, int j, int k) {
	std::cout << "[ remote_func ] " << i << " + " << j << " + " << k << " = " << i + j + k << "\n";
}

void main() {
	FILE* f = fopen("C:\\test\\Debug\\addr.txt", "w");
	fprintf(f, "%p", remote_function);
	fclose(f);

	while (true) {}
}
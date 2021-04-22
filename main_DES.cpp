
#include "DES.h"
#include "bmp.h"

int main() {
	srand(time(NULL));

	std::cout << "Using Data Encryption Standard algorythm \n";
	std::cout << "Please chose the cipher mode of operation:  0 - ECB, 1 - CFB" << std::endl;
	int CFBmode = 0;
	std::cin >> CFBmode;
	if ((CFBmode != 0) && (CFBmode != 1)) {
		std::cout << "Error! No such mode exists" << std::endl;
		getchar();
		exit(1);
	}
	std::cout << "Please choose the encryption mode: \n 0 - Automatic (generate key and initial vector) \n 1 - Manual (enter the key and initial vector) \n";
	int num = 0;
	std::cin >> num;
	if (num == 1) {
		std::cout << "Please, enter the key: ";
		std::string str;
		std::cin >> str;
		if (str.size() != 16) {
			std::cout << "Error! Key length should be 16" << std::endl;
			getchar();
			exit(1);
		}
		output("key.txt", str);

		str.clear();
		std::cout << "Please, enter the initial vector: ";
		std::cin >> str;
		if (str.size() != 16) {
			std::cout << "Error! vector length should be 16" << std::endl;
			getchar();
			exit(1);
		}
		output("IV.txt", str);
	}
	if (num == 0) {
		output("key.txt", random_str());
		output("IV.txt", random_str());
	}
	if ((num != 0) && (num != 1)) {
		std::cout << "Error! No such mode exists" << std::endl;
		getchar();
		exit(1);
	}

	uint64_t init_vect = inputf("IV.txt");
	uint64_t key = inputf("key.txt");
	generate_key(key);

	DES_txt("PeaceAndWar.txt", "encrypted-1.txt", false, CFBmode, init_vect);
	DES_txt("encrypted-1.txt", "decrypted-1.txt", true, CFBmode, init_vect);

	DES_bmp("11.bmp", "-encrypted.bmp", false, 0, init_vect);
	DES_bmp("daisy-encrypted.bmp", "daisy-derypted.bmp", true, 0, init_vect);

	DES_bmp("11.bmp", "-encrypted-cfb.bmp", false, 1, init_vect);
	DES_bmp("-encrypted-cfb.bmp", "-derypted-cfb.bmp", true, 1, init_vect);

	Make_err("input.txt", "encrypted-m.txt", false, CFBmode, init_vect);
	Make_err("encrypted-m.txt", "decrypted-m.txt", true, CFBmode, init_vect);

	return 0;
}

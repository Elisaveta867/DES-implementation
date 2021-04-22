#include <fstream>
#include "DES.h"

uint64_t sub_key[16]; 
uint64_t C;

uint64_t initial_permutation(uint64_t block) {
	uint64_t result = 0;
	for (int i = 0; i < 64; i++) {
		result <<= 1;
		result |= (block >> (64 - initialPerm[i])) & 1;
	}
	return result;
}

uint64_t final_permutation(uint64_t block) {
	uint64_t result = 0;
	for (int i = 0; i < 64; i++) {
		result <<= 1;
		result |= (block >> (64 - finalPerm[i])) & 1;
	}
	return result;
}

void initialise(uint64_t IV) {
	C = IV;
}

uint64_t CFB_encr(uint64_t block) {
	C = DES(C, false) ^ block;
	return C;
}

uint64_t CFB_decr(uint64_t block) {
	uint64_t next_block = block ^ DES(C, false);
	C = block;
	return next_block;
}

uint32_t convertionF(uint32_t right, uint64_t key) { //ф
	uint64_t s = 0;
	for (uint8_t i = 0; i < 48; i++) {
		s <<= 1;
		s |= (uint64_t)((right >> (32 - expancionPerm[i])) & 1);
	}

	s = s ^ key;

	uint32_t s_block = 0;
	for (int i = 0; i < 8; i++) {
		char row = (char)((s & (0x840000000000 >> 6 * i)) >> (42 - 6 * i));
		row = (row >> 4) | (row & 0x01);

		char column = (char)((s & (0x780000000000 >> 6 * i)) >> (43 - 6 * i));

		s_block <<= 4;
		s_block |= (uint32_t)(SBOX[i][16 * row + column]);
	}

	uint32_t f_result = 0;
	for (int i = 0; i < 32; i++) {
		f_result <<= 1;
		f_result |= (s_block >> (32 - PT[i])) & 1;
	}

	return f_result;
}

uint64_t DES(uint64_t block, bool flag) {
	block = initial_permutation(block);
	
	uint32_t left = (uint32_t)(block >> 32) & 0x00000000ffffffff;
	uint32_t right = (uint32_t)(block & 0x00000000ffffffff);

	for (int i = 0; i < 16; i++) {
		uint32_t F;
		if (flag) {
			F = convertionF(right, sub_key[15 - i]);
		}
		else {
			F = convertionF(right, sub_key[i]);
		}
		uint32_t temp = right;
		right = left ^ F;
		left = temp;
	}

	block = (((uint64_t)right) << 32) | (uint64_t)left;

	return final_permutation(block);
}

void generate_key(uint64_t key) {
	uint64_t expansion_key = 0; // 56 бит
	for (int i = 0; i < 56; i++) {
		expansion_key <<= 1;
		expansion_key |= (key >> (64 - funcB[i])) & 1; //применение функции В
	}

	// по 28 бит
	uint32_t C = (uint32_t)((expansion_key >> 28) & 0x000000000fffffff);
	uint32_t D = (uint32_t)(expansion_key & 0x000000000fffffff);

	for (int i = 0; i < 16; i++) {
		for (int j = 0; j < Shift[i]; j++) {
			C = (0x0fffffff & (C << 1)) | (0x00000001 & (C >> 27));
			D = (0x0fffffff & (D << 1)) | (0x00000001 & (D >> 27));
		}

		uint64_t new_key = (((uint64_t)C) << 28) | (uint64_t)D;

		sub_key[i] = 0;
		for (int j = 0; j < 48; j++) {
			sub_key[i] <<= 1;
			sub_key[i] |= (new_key >> (56 - permK[j])) & 1; //сжимающая перестановка K
		}
	}
}

void DES_txt(std::string input, std::string output, bool flag, bool CFB, uint64_t init_vect) {
	std::ifstream inputfile;
	std::ofstream outputfile;
	uint64_t buf;
	if (CFB) initialise(init_vect);

	inputfile.open(input, std::ios::binary | std::ios::in | std::ios::ate);
	outputfile.open(output, std::ios::binary | std::ios::out);

	uint64_t size = inputfile.tellg();
	inputfile.seekg(0, std::ios::beg);

	uint64_t block = size / 8;
	if (flag) block--;

	for (uint64_t i = 0; i < block; i++) {
		inputfile.read((char*)&buf, 8);
		if (CFB) {
			if (i == 0) buf = 0;
			if (flag) buf = CFB_decr(buf);
			else buf = CFB_encr(buf);
		}
		else {
			if (i == 0) buf = 0;
			if (flag) buf = DES(buf, true);
			else buf = DES(buf, false);
		}

		outputfile.write((char*)&buf, 8);
	}

	if (flag == false) {
		uint8_t padding = 8 - (size % 8);

		if (padding == 0)
			padding = 8;

		buf = (uint64_t)0;
		if (padding != 8) inputfile.read((char*)&buf, 8 - padding);

		uint8_t shift = padding * 8;
		buf <<= shift;
		buf |= (uint64_t)0x0000000000000001 << (shift - 1);

		if (CFB) buf = CFB_encr(buf);
		else buf = DES(buf, false);

		outputfile.write((char*)&buf, 8);
	}
	else {
		inputfile.read((char*)&buf, 8);

		if (CFB) buf = CFB_decr(buf);
		else buf = DES(buf, true);

		uint8_t padding = 0;

		while (!(buf & 0x00000000000000ff)) {
			buf >>= 8;
			padding++;
		}

		buf >>= 8;
		padding++;

		if (padding != 8) outputfile.write((char*)&buf, 8 - padding);
	}

	inputfile.close();
	outputfile.close();
}

void DES_bmp(std::string input, std::string output, bool flag, bool CFB, uint64_t init_vect) {
	std::ifstream inputfile;
	std::ofstream outputfile;
	uint64_t buf;
	if (CFB) initialise(init_vect);

	inputfile.open(input, std::ios::binary | std::ios::in);
	outputfile.open(output, std::ios::binary | std::ios::out);

	std::vector<char> head(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER));

	inputfile.seekg(0, std::ios::end);
	uint64_t size = inputfile.tellg();

	inputfile.seekg(0, std::ios::beg);
	inputfile.read(&head[0], head.size());
	outputfile.write(&head[0], head.size());
	size = size - (uint64_t)head.size();

	uint64_t block = size / 8;
	if (flag) block--;

	for (uint64_t i = 0; i < block; i++) {
		inputfile.read((char*)&buf, 8);

		if (CFB) {
			if (i == 0) buf = 0;
			if (flag) buf = CFB_decr(buf);
			else buf = CFB_encr(buf);
		}
		else {
			if (i == 0) buf = 0;
			if (flag) buf = DES(buf, true);
			else buf = DES(buf, false);
		}
		
		outputfile.write((char*)&buf, 8);
	}

	if (flag == false) {
		uint8_t padding = 8 - (size % 8);

		if (padding == 0)
			padding = 8;

		buf = (uint64_t)0;
		if (padding != 8) inputfile.read((char*)&buf, 8 - padding);

		uint8_t shift = padding * 8;
		buf <<= shift;
		buf |= (uint64_t)0x0000000000000001 << (shift - 1);

		if (CFB) buf = CFB_encr(buf);
		else buf = DES(buf, false);
		outputfile.write((char*)&buf, 8);
	}
	else {
		inputfile.read((char*)&buf, 8);
		if (CFB) buf = CFB_decr(buf);
		else buf = DES(buf, true);

		uint8_t padding = 0;

		while (!(buf & 0x00000000000000ff)) {
			buf >>= 8;
			padding++;
		}

		buf >>= 8;
		padding++;

		if (padding != 8) outputfile.write((char*)&buf, 8 - padding);
	}
	inputfile.close();
	outputfile.close();
}

void Make_err(std::string input, std::string output, bool flag, bool CFB, uint64_t init_vect) {
	std::ifstream inputfile;
	std::ofstream outputfile;
	uint64_t buf;
	if (CFB) initialise(init_vect);

	inputfile.open(input, std::ios::binary | std::ios::in | std::ios::ate);
	outputfile.open(output, std::ios::binary | std::ios::out);

	uint64_t size = inputfile.tellg();
	inputfile.seekg(0, std::ios::beg);

	uint64_t block = size / 8;
	if (flag) block--;

	for (uint64_t i = 0; i < block; i++) {
		inputfile.read((char*)&buf, 8);
		if (CFB) {
			if (i == 0) buf = buf ^ (1 << 22);
			if (flag) buf = CFB_decr(buf);
			else buf = CFB_encr(buf);
		}
		else {
			if (i == 0) buf = buf ^ (1 << 22);
			if (flag) buf = DES(buf, true);
			else buf = DES(buf, false);
		}

		outputfile.write((char*)&buf, 8);
	}

	if (flag == false) {
		uint8_t padding = 8 - (size % 8);

		if (padding == 0)
			padding = 8;

		buf = (uint64_t)0;
		if (padding != 8) inputfile.read((char*)&buf, 8 - padding);

		uint8_t shift = padding * 8;
		buf <<= shift;
		buf |= (uint64_t)0x0000000000000001 << (shift - 1);

		if (CFB) buf = CFB_encr(buf);
		else buf = DES(buf, false);

		outputfile.write((char*)&buf, 8);
	}
	else {
		inputfile.read((char*)&buf, 8);

		if (CFB) buf = CFB_decr(buf);
		else buf = DES(buf, true);

		uint8_t padding = 0;

		while (!(buf & 0x00000000000000ff)) {
			buf >>= 8;
			padding++;
		}

		buf >>= 8;
		padding++;

		if (padding != 8) outputfile.write((char*)&buf, 8 - padding);
	}

	inputfile.close();
	outputfile.close();
}

uint64_t inputf(std::string str) {
	std::ifstream inputfile;
	uint64_t buf;
	inputfile.open(str, std::ios::binary | std::ios::in);
	inputfile.read((char*)&buf, 8);
	inputfile.close();
	return buf;
}

void output(std::string output, std::string data) {
	std::ofstream outputfile;
	outputfile.open(output, std::ios::out);
	outputfile << data;
	outputfile.close();
}

std::string random_str() {
	std::string key;
	static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	for (int i = 0; i < 16; ++i) {
		key += alphanum[rand() % (sizeof(alphanum) - 1)];
	}
	return key;
}

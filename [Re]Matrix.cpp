#include"[Re]Matrix.h"

struct info_file
{
	BYTE* data_file;
	SIZE_T szFile;
};

info_file* readFileBuff()
{
	HANDLE hFile = CreateFile(L"C:\\Users\\user\\Desktop\\temp\\matrix.bin", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile)
	{
		int szFile = GetFileSize(hFile, 0);
		BYTE* data_file = (BYTE*)malloc(szFile);
		ReadFile(hFile, data_file, szFile, NULL, NULL);
		struct info_file* infFile = new info_file;
		infFile->szFile = szFile;
		infFile->data_file = data_file;
		CloseHandle(hFile);
		return infFile;
	}
	else
	{
		int error_code = GetLastError();
		printf("Can't read file, error code %x\n", error_code);
		return nullptr;
	}
}

struct my_struct
{
	void* base;
	short flag;
	BYTE* buff1;
	BYTE* buff2;
	void* func_getc;
	void* func_putc;
};

struct local_v
{
	BYTE val1;
	WORD val2;
};

bool procced(my_struct* my, local_v* param2);

BYTE* buff1 = nullptr;
BYTE* buff2 = nullptr;

void solve()
{
	struct info_file* info = nullptr;
	buff1 = (BYTE*)malloc(0x800);
	ZeroMemory(buff1, 0x800);
	buff2 = (BYTE*)malloc(0x800);
	ZeroMemory(buff2, 0x800);
	info = readFileBuff();
	
	if (info)
	{
		struct my_struct* my_st = new my_struct;
		struct local_v* local_var = new local_v;
		my_st->base = info->data_file;
		my_st->buff1 = buff1;
		my_st->buff2 = buff2;
		my_st->func_getc = getc;
		my_st->func_putc = putc;
		my_st->flag = 0;
		int ret = 0;
		do
		{
			ret = procced(my_st, local_var);
		} while (ret);
		if (local_var->val1 == 0)
		{
			if (local_var->val2 == 0)
			{
				printf("Have a flag");
			}
		}
		free(info->data_file);
		delete info;
		delete local_var;
	}
	free(buff1);
	free(buff2);
}

bool procced(my_struct* base, local_v* flag)
{
	WORD temp, temp1, temp2;
	BYTE* local_base = (BYTE*)base->base;
	WORD pre_count = base->flag;
	WORD next_count = pre_count + 1;
	base->flag = next_count;
	//std::cout << "jmp to " << std::hex << pre_count << "\n";
	BYTE byte_got = *(local_base + pre_count);
	switch (byte_got)
	{
	case 0:
		//std::cout << "pause 0\n";
		return 0;
	case 1:
		//std::cout << "pause 1 \n";
		return 0;
	case 0x10:
		//duplicate
		//std::cout << "dup\n";
		*(WORD*)base->buff1 = *(WORD*)(base->buff1 - 2);
		base->buff1 += 2;
		return 1;
	case 0x11:
		//pop 2 bytes
		//std::cout << "pop\n";
		base->buff1 -= 2;
		return 1;
	case 0x12:
		//std::cout << "add\n";
		// add
		*(WORD*)(base->buff1 - 4) = *(WORD*)(base->buff1 - 4) + *(WORD*)(base->buff1 - 2);
		base->buff1 -= 2;
		return 1;
	case 0x13:
		//std::cout << "sub\n";
		//sub
		*(WORD*)(base->buff1 - 4) = *(WORD*)(base->buff1 - 4) - *(WORD*)(base->buff1 - 2);
		base->buff1 -= 2;
		return 1;
	case 0x14:
		//std::cout << "swap\n";
		//swap value
		temp = *(WORD*)(base->buff1 - 4);
		*(WORD*)(base->buff1 - 4) = *(WORD*)(base->buff1 - 2);
		*(WORD*)(base->buff1 - 2) = temp;
		return 1;
	case 0x20:
		//std::cout << "copy to buff2\n";
		//copy value buff1 -> buff2
		*(WORD*)(base->buff2) = *(WORD*)(base->buff1 - 2);
		base->buff1 -= 2;
		base->buff2 += 2;
		return 1;
	case 0x21:
		//std::cout << "copty to buff1\n";
		//copy value buff2 -> buff1
		*(WORD*)(base->buff1) = *(WORD*)(base->buff2 - 2);
		base->buff2 -= 2;
		base->buff1 += 2;
		return 1;
	case 0x30:
		base->flag = *(WORD*)(base->buff1 - 2);
		base->buff1 -= 2;
		return 1;
	case 0x31:
		temp = *(WORD*)(base->buff1 - 2);
		temp1 = *(WORD*)(base->buff1 - 4);
		base->buff1 -= 4;
		if (temp1 == 0)
		{
LAB_154b:
			base->flag = temp;
		}
		return 1;
	case 0x32:
		temp = *(WORD*)(base->buff1 - 2);
		temp1 = *(WORD*)(base->buff1 - 4);
		base->buff1 -= 4;
		if (temp1 != 0)
			goto LAB_154b;
		break;
	case 0x33:
		temp = *(WORD*)(base->buff1 - 2);
		temp1 = *(WORD*)(base->buff1 - 4);
		base->buff1 -= 4;
		if (temp1 < 0)
			goto LAB_154b;
		break;
	case 0x34:
		temp = *(WORD*)(base->buff1 - 2);
		temp1 = *(WORD*)(base->buff1 - 4);
		base->buff1 -= 4;
		if (temp1 < 1)
			goto LAB_154b;
		break;
	default:
		if (byte_got == 0xc0)
		{
			//get 1 char
			*(WORD*)(base->buff1) = (WORD)getc(stdin);
			base->buff1 += 2;
			return 1;
		}
		if (byte_got < 0xc1)
		{
			BYTE step, sVar5;
			if (byte_got == 0x80)
			{
				base->flag = 0x2 + pre_count;
				//std::cout << "push " << std::hex << (WORD) * (BYTE*)(local_base + next_count) << "\n";
				//std::cout << "offset " << std::hex << next_count << "\n";
				*(WORD*)(base->buff1) = (WORD)*(BYTE*)(local_base + next_count);
			}
			else
			{
				if(byte_got != 0x81) goto LAB_RETURN;
				base->flag = 3 + pre_count;
				//std::cout << "push " << std::hex << *(WORD*)(local_base + next_count) << "\n";
				//std::cout << "offset " << std::hex << next_count << "\n";
				*(WORD*)(base->buff1) = *(WORD*)(local_base + next_count);
			}
			base->buff1 += 2;
			return 1;
		}
		if (byte_got == 0xc1)
		{
			//call putc
			putc(*(WORD*)(base->buff1 - 2), stdout);
			base->buff1 -= 2;
			return 1;
		}
	}
	return 1;
LAB_RETURN:
	if (flag == 0)
		return 0;
	flag->val1 = 1;
	return 0;
}

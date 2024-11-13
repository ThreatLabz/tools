#include <Windows.h>
#include <stdio.h>
#include <thread>

unsigned int globalThreadCounter = 0;
bool stopThread = false;

void monitorThread()
{
	while (!stopThread)
	{
		globalThreadCounter += 1;
	}
}

int main(int argc, char** argv)
{
	const unsigned int successfullMeasurementLimit = 6;
	const unsigned int successfullAttemptsLimit = 6;
	int successFullAttempts = 0;
	const size_t readSize = 0x00FB6000;
	const size_t expectedReadMemoryBytesSum = 0xDDEAC000;

	unsigned char* allocatedMemory = (unsigned char*)VirtualAlloc(NULL, readSize, MEM_COMMIT | MEM_RESERVE, PAGE_WRITECOMBINE | PAGE_READWRITE);
	if (!allocatedMemory)
	{
		printf("Failed to allocate memory\n");
		return -1;
	}
	std::thread monitorT(monitorThread);
	// Independent from current thread
	monitorT.detach();
	for (int i = 0; i < 32; i++)
	{
		unsigned int beforeWriteMemoryThreadCounter = globalThreadCounter;
		size_t writeLoopCounter = 0;
		while (writeLoopCounter < readSize)
		{
			allocatedMemory[writeLoopCounter] = 0xE2;
			writeLoopCounter += 1;
		}
		unsigned int afterWriteMemoryThreadCounter = (globalThreadCounter - beforeWriteMemoryThreadCounter) >> 4;
		size_t readLoopCounter = 0;
		size_t loopMemoryReadBytesSum = 0;
		unsigned int beforeReadMemoryThreadCounter = globalThreadCounter;
		while(readLoopCounter < readSize)
		{
			unsigned char memoryByte = allocatedMemory[readLoopCounter];
			readLoopCounter += 1;
			loopMemoryReadBytesSum += memoryByte;
		}
		unsigned int afterReadMemoryThreadCounter = (globalThreadCounter - beforeReadMemoryThreadCounter) >> 4;
		unsigned int result = 0;
		if (expectedReadMemoryBytesSum == loopMemoryReadBytesSum && afterWriteMemoryThreadCounter)
		{ 
			result = afterReadMemoryThreadCounter / afterWriteMemoryThreadCounter;
		}
		if (result >= successfullMeasurementLimit)
			successFullAttempts += 1;
	}
	stopThread = true;
	VirtualFree(allocatedMemory, 0, MEM_RELEASE);
	if (successFullAttempts >= successfullAttemptsLimit)
	{
		printf(“Detection passed successfully\n”);
	}
	else
	{
		printf(“Failed to pass detection\n”);
	}
	return 0;
} 


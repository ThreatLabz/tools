import struct, lznt1, sys
import argparse


def findOffset(file, searchByte, Startoffset):
 resultOffset = file.index(searchByte, Startoffset +1)
 return resultOffset


def decryptPayload(file, xorKey, payloadSize):
 while payloadSize % 4 != 0 :
  payloadSize =payloadSize -1
  
 for i in range(0, payloadSize, 4):
  file.seek(i)
  data = file.read(4)
  data = struct.unpack('<I', data)[0]
  data = data ^ xorKey
  data = struct.pack('<I', data)
  file.seek(i)
  file.write(data)


def processfile(malware_file): 
    checkFlag = 0
    with open(malware_file, "rb") as input_file:
      input_file.seek(0)
      file = input_file.read()
      offset = 0
      
      try:
       resultOffsetNextByte = file.index(b'\x49\x44\x41\x54\xC6\xA5\x79\xEA', offset + 1)
       print("Found HijackLoader PNG image")
       checkFlag = 1
        
      except ValueError:
        print('Could not find PNG with correct HijackLoader header')
        sys.exit(1)

      if checkFlag == 1:
       input_file.seek(resultOffsetNextByte - 4)
       size = input_file.read(4)
       size = struct.unpack('>I', size)[0]
       configDataCheck1 = input_file.read(4)
       configDataCheck1 = struct.unpack('<I', configDataCheck1)[0]
       configDataCheck2 = input_file.read(4)
       configDataCheck2 = struct.unpack('<I', configDataCheck2)[0]
       configDataCheck3 = input_file.read(4)
       xorKey = struct.unpack('<I', configDataCheck3)[0]
       
      Size1 = input_file.read(4)
      Size1 = struct.unpack('<I', Size1)[0]
      print("Total size: "+hex(Size1))
      currentSize = 0
      size = size - 0x10
      with open(r"secondstage.bin", "ab+") as output_file:
       while Size1 > currentSize + size:
        idat = input_file.read(4)
        payload_encrypted = input_file.read(size)
        output_file.write(payload_encrypted)
        currentSize = currentSize + size
        currentSize = currentSize & 0xFFFFFFFF
        resultOffsetNextByte = findOffset(file, b'\x49\x44\x41\x54', resultOffsetNextByte+1)
        input_file.seek(resultOffsetNextByte - 4 )
        size = input_file.read(4)
        size = struct.unpack('>I', size)[0]
        size = size & 0xFFFFFFFF 
        
       remainingSize = Size1 - currentSize
       input_file.seek(resultOffsetNextByte)
       idat = input_file.read(4)
       payload_encrypted = input_file.read(remainingSize)
       output_file.write(payload_encrypted)
       print("[+] Encypted second stage written to disk")
       
      with open(r"secondstage.bin", "rb+") as operation_file:
       payloadSize = Size1
       decryptPayload(operation_file, xorKey, payloadSize)
       print("[+] Second stage successfully decrypted")

    with open(r"secondstage.bin", "rb+") as operation_file:
     readBytes = operation_file.read()
     decompressedData = lznt1.decompress(readBytes)
     with open(r"secondstage_decompressed.bin", "wb") as last_file:
      last_file.write(decompressedData)
      print("[+] Second stage decompressed")
      
    with open(r"secondstage_decompressed.bin", "rb+") as last_file:
       last_file.seek(0xf4)
       dll = ''.join(iter(lambda: last_file.read(1).decode('ascii'), '\x00'))
       print("DLL to perform module stomping: "+dll)
       last_file.seek(0x90)
       folderName = ''.join(iter(lambda: last_file.read(1).decode('ascii'), '\x00'))
       print("Process which is created to perform next stage injection: "+folderName)
       last_file.seek(8)
       offset = last_file.read(4)
       offset = struct.unpack('<I', offset )[0]
       offset = offset + 0x3DD
       comparisonOffset = offset + 0xee4
       last_file.seek(comparisonOffset)
       compoffset = last_file.read(4)
       compoffset = struct.unpack('<I', compoffset )[0]
       i = 0
       while True:
        if compoffset <= i:
         break
        muler= i * 0x84
        tempoffset = offset + 0x10de + muler + 6 * i
        last_file.seek(tempoffset)
        moduleName = ''.join(iter(lambda: last_file.read(1).decode('ascii'), '\x00'))
        
        muler= i * 0x84
        sizeoffset = offset + 0x1164 + muler + i * 6
        last_file.seek(sizeoffset)
        tsize = last_file.read(4)
        tsize2 = struct.unpack('<I', tsize )[0]
        
        muler= i * 0x84
        sizeoffset = offset + 0x1160 + muler + i * 6
        last_file.seek(sizeoffset)
        tsize = last_file.read(4)
        tsize = struct.unpack('<I', tsize )[0]
        address = offset + 0xee4 + tsize 
        last_file.seek(address)
        injected_payload = last_file.read(tsize2)
        with open(moduleName+".bin", "ab+") as inj_file:
         inj_file.write(injected_payload)
        print("[+] "+moduleName+" module written to disk")
        i= i + 1
        
    
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file_path', help="Path to HijackLoader sample containing Embedded PNG", type=str, required=True)
    args = parser.parse_args()
    malware_file = f"{args.file_path}"
    malware_file = str(malware_file)
    processfile(malware_file)
    

if __name__ == '__main__':
    main()

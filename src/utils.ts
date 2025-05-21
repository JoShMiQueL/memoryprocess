// @ts-nocheck
// TODO: In the future, we plan to add proper typing
const SIZEOF_STDSTRING_32BIT = 24;
const SIZEOF_STDSTRING_64BIT = 32;
const STDSTRING_LENGTH_OFFSET = 0x10;

/**
 * Custom string consumer/producer for Structron (due to complexity of `std::string`)
 * `std::string` is a container for a string which makes reading/writing to it tricky,
 * it will either store the string itself, or a pointer to the string, based on the
 * length of the string. When we want to read from or write to a buffer, we need
 * to determine if the string is in the buffer itself, or if the buffer
 * just contains a pointer to the string. Based on one of these options,
 * we can read from or write to the string.
 *
 * @param handle the handle to the process
 * @param structAddress the base address of the structure in memory
 * @param platform the architecture of the process, either "32" or "64"
 * @param encoding the encoding type of the string
 */
export const STRUCTRON_TYPE_STRING = memoryprocess => {
  if (!memoryprocess || typeof memoryprocess.readMemory !== 'function' || 
      typeof memoryprocess.readBuffer !== 'function' || typeof memoryprocess.writeMemory !== 'function') {
    throw new Error('Invalid memoryprocess object provided to STRUCTRON_TYPE_STRING factory.');
  }

  return (handle, structAddress, platform, encoding = 'utf8') => {
    if (typeof handle !== 'number' || handle < 0) {
      throw new Error('Invalid handle: must be a non-negative number.');
    }
    if (typeof structAddress !== 'number' || structAddress <= 0) { // structAddress should generally be positive
      throw new Error('Invalid structAddress: must be a positive number.');
    }
    if (platform !== '32' && platform !== '64') {
      throw new Error('Invalid platform: must be "32" or "64".');
    }
    if (typeof encoding !== 'string') {
      throw new Error('Invalid encoding: must be a string.');
    }

    const expectedSize = platform === '64' ? SIZEOF_STDSTRING_64BIT : SIZEOF_STDSTRING_32BIT;

    return {
      read(buffer, offset) {
        if (!(buffer instanceof Buffer)) {
          throw new Error('Invalid buffer: argument must be a Buffer instance.');
        }
        if (typeof offset !== 'number' || offset < 0) {
          throw new Error('Invalid offset: must be a non-negative number.');
        }
        if (offset + STDSTRING_LENGTH_OFFSET + 4 > buffer.length) { // 4 bytes for length
          throw new Error('Buffer underflow: not enough space to read string length.');
        }

        // get string length from `std::string` container
        const length = buffer.readUInt32LE(offset + STDSTRING_LENGTH_OFFSET);

        // if length > 15, `std::string` has a pointer to the string
        if (length > 15) {
          if (offset + (platform === '64' ? 8 : 4) > buffer.length) { // 8 for uint64, 4 for uint32 pointer
            throw new Error('Buffer underflow: not enough space to read string pointer.');
          }
          const pointer = platform === '64' ? buffer.readBigInt64LE(offset) : buffer.readUInt32LE(offset);
          if (Number(pointer) <= 0) {
            throw new Error('Invalid string pointer in std::string container (points to null or zero).');
          }
          return memoryprocess.readMemory(handle, Number(pointer), 'string');
        }

        // if length <= 15, `std::string` directly contains the string
        if (offset + length > buffer.length) {
          throw new Error('Buffer underflow: string length exceeds buffer size for inline string.');
        }
        return buffer.toString(encoding, offset, offset + length);
      },
      write(value, context, offset) {
        if (typeof value !== 'string') {
          throw new Error('Invalid value: must be a string to write.');
        }
        if (!context || !(context.buffer instanceof Buffer)) {
          throw new Error('Invalid context: context.buffer must be a Buffer instance.');
        }
        if (typeof offset !== 'number' || offset < 0) {
          throw new Error('Invalid offset: must be a non-negative number.');
        }
        if (offset + expectedSize > context.buffer.length) {
          throw new Error('Buffer overflow: not enough space in context.buffer for std::string container.');
        }

        // address containing the length of the string
        const lengthAddress = structAddress + offset + STDSTRING_LENGTH_OFFSET;

        // get existing `std::string` buffer
        const bufferSize = expectedSize; // Use already calculated expectedSize
        const existingBuffer = memoryprocess.readBuffer(handle, structAddress + offset, bufferSize);
        if (existingBuffer.length !== bufferSize) {
          throw new Error(`Failed to read existing std::string buffer. Expected ${bufferSize}, got ${existingBuffer.length}`);
        }

        // fetch length of string in memory (to determine if it's pointer based)
        const lengthInMemory = memoryprocess.readMemory(handle, lengthAddress, 'int');
        if (typeof lengthInMemory !== 'number') {
           throw new Error(`Failed to read string length from memory at address ${lengthAddress}.`);
        }


        if ((lengthInMemory > 15 && value.length <= 15) || (lengthInMemory <= 15 && value.length > 15)) {
          // there are two ways strings are stored: directly or with a pointer,
          // we can't go from one to the other (without introducing more complexity),
          // so just skip the bytes to prevent crashing. if a pointer is used, we could
          // technically write any length, but the next time we try writing, we will read
          // the length and assume it's not stored via pointer and will lead to crashes

          // write existing buffer without changes
          existingBuffer.copy(context.buffer, offset);
          return;
        }

        // write new length
        memoryprocess.writeMemory(handle, lengthAddress, value.length, 'uint32');
        existingBuffer.writeUInt32LE(value.length, STDSTRING_LENGTH_OFFSET);

        if (lengthInMemory > 15 && value.length > 15) {
          // write new string in memory
          const pointer = memoryprocess.readMemory(handle, structAddress + offset, 'pointer');
          if (Number(pointer) <= 0) {
            throw new Error('Invalid string pointer in existing std::string container (points to null or zero).');
          }
          memoryprocess.writeMemory(handle, Number(pointer), value, 'string');
        } else if (lengthInMemory <= 15 && value.length <= 15) {
          // write new string directly into buffer
          // Ensure existingBuffer has enough space for the inline string (max 15 chars + null terminator for safety, though std::string might not null terminate inline part)
          // The first part of std::string buffer is where inline string is stored.
          if (value.length > 15) { // Should not happen due to earlier check, but as safeguard
             throw new Error("Internal error: trying to write string longer than 15 chars directly into std::string buffer.");
          }
          existingBuffer.write(value, 0, value.length, encoding); // Write at the beginning of the buffer
          // Clear remaining part of the inline buffer area if new string is shorter than old one
          for (let i = value.length; i < Math.min(16, lengthInMemory); i++) {
            existingBuffer[i] = 0;
          }
        }

        // write our new `std::string` buffer into the buffer we are creating
        existingBuffer.copy(context.buffer, offset);
      },
      SIZE: expectedSize,
    };
  };
};
      // there are two ways strings are stored: directly or with a pointer,
      // we can't go from one to the other (without introducing more complexity),
      // so just skip the bytes to prevent crashing. if a pointer is used, we could
      // technically write any length, but the next time we try writing, we will read
      // the length and assume it's not stored via pointer and will lead to crashes

      // write existing buffer without changes
      existingBuffer.copy(context.buffer, offset);
      return;
    }

    // write new length
    memoryprocess.writeMemory(handle, lengthAddress, value.length, 'uint32');
    existingBuffer.writeUInt32LE(value.length, STDSTRING_LENGTH_OFFSET);

    if (length > 15 && value.length > 15) {
      // write new string in memory
      const pointer = memoryprocess.readMemory(handle, structAddress + offset, 'pointer');
      memoryprocess.writeMemory(handle, pointer, value, 'string');
    } else if (length <= 15 && value.length <= 15) {
      // write new string directly into buffer
      existingBuffer.write(value, encoding);
    }

    // write our new `std::string` buffer into the buffer we are creating
    existingBuffer.copy(context.buffer, offset);
  },
  SIZE: platform === '64' ? SIZEOF_STDSTRING_64BIT : SIZEOF_STDSTRING_32BIT,
});

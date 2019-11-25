<?php


namespace Cijber\OpenSSL;


use Cijber\OpenSSL;
use Cijber\OpenSSL\C\CBackedObjectWithOwner;
use RuntimeException;

class BIO extends CBackedObjectWithOwner
{
    const CTRL_RESET = 1;
    const CTRL_EOF = 2;
    const CTRL_INFO = 3;
    const CTRL_SET = 4;
    const CTRL_GET = 5;
    const CTRL_PUSH = 6;
    const CTRL_POP = 7;
    const CTRL_GET_CLOSE = 8;
    const CTRL_SET_CLOSE = 9;
    const CTRL_PENDING = 10;
    const CTRL_FLUSH = 11;
    const CTRL_DUP = 12;
    const CTRL_WPENDING = 13;
    const CTRL_SET_CALLBACK = 14;
    const CTRL_GET_CALLBACK = 15;
    const CTRL_SET_FILENAME = 30;
    const CTRL_DGRAM_CONNECT = 31;
    const CTRL_DGRAM_SET_CONNECTED = 32;
    const CTRL_DGRAM_SET_RECV_TIMEOUT = 33;
    const CTRL_DGRAM_GET_RECV_TIMEOUT = 34;
    const CTRL_DGRAM_SET_SEND_TIMEOUT = 35;
    const CTRL_DGRAM_GET_SEND_TIMEOUT = 36;
    const CTRL_DGRAM_GET_RECV_TIMER_EXP = 37;
    const CTRL_DGRAM_GET_SEND_TIMER_EXP = 38;
    const CTRL_DGRAM_MTU_DISCOVER = 39;
    const CTRL_DGRAM_QUERY_MTU = 40;
    const CTRL_DGRAM_GET_FALLBACK_MTU = 47;
    const CTRL_DGRAM_GET_MTU = 41;
    const CTRL_DGRAM_SET_MTU = 42;
    const CTRL_DGRAM_MTU_EXCEEDED = 43;
    const CTRL_DGRAM_GET_PEER = 46;
    const CTRL_DGRAM_SET_PEER = 44;
    const CTRL_DGRAM_SET_NEXT_TIMEOUT = 45;

    const C_SET_CONNECT = 100;
    const C_DO_STATE_MACHINE = 101;
    const C_SET_NBIO = 102;
    const C_SET_PROXY_PARAM = 103;
    const C_SET_FD = 104;
    const C_GET_FD = 105;
    const C_SET_FILE_PTR = 106;
    const C_GET_FILE_PTR = 107;
    const C_SET_FILENAME = 108;
    const C_SET_SSL = 109;
    const C_GET_SSL = 110;
    const C_SET_MD = 111;
    const C_GET_MD = 112;
    const C_GET_CIPHER_STATUS = 113;
    const C_SET_BUF_MEM = 114;
    const C_GET_BUF_MEM_PTR = 115;
    const C_GET_BUFF_NUM_LINES = 116;
    const C_SET_BUFF_SIZE = 117;
    const C_SET_ACCEPT = 118;
    const C_SSL_MODE = 119;
    const C_GET_MD_CTX = 120;
    const C_GET_PROXY_PARAM = 121;
    /**
     * data to read first
     */
    const C_SET_BUFF_READ_DATA = 122;
    const C_GET_CONNECT = 123;
    const C_GET_ACCEPT = 124;
    const C_SET_SSL_RENEGOTIATE_BYTES = 125;
    const C_GET_SSL_NUM_RENEGOTIATES = 126;
    const C_SET_SSL_RENEGOTIATE_TIMEOUT = 127;
    const C_FILE_SEEK = 128;
    const C_GET_CIPHER_CTX = 129;
    /**
     * return end of input value
     */
    const C_SET_BUF_MEM_EOF_RETURN = 130;
    const C_SET_BIND_MODE = 131;
    const C_GET_BIND_MODE = 132;
    const C_FILE_TELL = 133;
    const C_GET_SOCKS = 134;
    const C_SET_SOCKS = 135;
    /**
     * for BIO_s_bio
     */
    const C_SET_WRITE_BUF_SIZE = 136;
    const C_GET_WRITE_BUF_SIZE = 137;
    const C_MAKE_BIO_PAIR = 138;
    const C_DESTROY_BIO_PAIR = 139;
    const C_GET_WRITE_GUARANTEE = 140;
    const C_GET_READ_REQUEST = 141;
    const C_SHUTDOWN_WR = 142;
    const C_NREAD0 = 143;
    const C_NREAD = 144;
    const C_NWRITE0 = 145;
    const C_NWRITE = 146;
    const C_RESET_READ_REQUEST = 147;
    const C_SET_MD_CTX = 148;
    const C_SET_PREFIX = 149;
    const C_GET_PREFIX = 150;
    const C_SET_SUFFIX = 151;
    const C_GET_SUFFIX = 152;
    const C_SET_EX_ARG = 153;
    const C_GET_EX_ARG = 154;


    const TYPE_NONE = 0;
    const TYPE_MEM = (1 | 0x0400);
    const TYPE_FILE = (2 | 0x0400);
    const TYPE_FD = (4 | 0x0400 | 0x0100);
    const TYPE_SOCKET = (5 | 0x0400 | 0x0100);
    const TYPE_NULL = (6 | 0x0400);
    const TYPE_SSL = (7 | 0x0200);
    /**
     * passive filter
     */
    const TYPE_MD = (8 | 0x0200);
    /**
     * filter
     */
    const TYPE_BUFFER = (9 | 0x0200);
    /**
     * filter
     */
    const TYPE_CIPHER = (10 | 0x0200);
    /**
     * filter
     */
    const TYPE_BASE64 = (11 | 0x0200);

    /**
     * socket - connect
     */
    const TYPE_CONNECT = (12 | 0x0400 | 0x0100);
    /**
     * socket for accept
     */
    const TYPE_ACCEPT = (13 | 0x0400 | 0x0100);
    /**
     * client proxy BIO
     */
    const TYPE_PROXY_CLIENT = (14 | 0x0200);
    /**
     * server proxy BIO
     */
    const TYPE_PROXY_SERVER = (15 | 0x0200);
    /**
     * server proxy BIO
     */
    const TYPE_NBIO_TEST = (16 | 0x0200);
    const TYPE_NULL_FILTER = (17 | 0x0200);
    /**
     * BER -> bin filter
     */
    const TYPE_BER = (18 | 0x0200);
    /**
     * (half a) BIO pair
     */
    const TYPE_BIO = (19 | 0x0400);
    /**
     * filter
     */
    const TYPE_LINEBUFFER = (20 | 0x0200);
    const TYPE_DGRAM = (21 | 0x0400 | 0x0100);
    /**
     * filter
     */
    const TYPE_ASN1 = (22 | 0x0200);
    /**
     * filter
     */
    const TYPE_COMP = (23 | 0x0200);
    /**
     * socket, fd, connect or accept
     */
    const TYPE_DESCRIPTOR = 0x0100;
    const TYPE_FILTER = 0x0200;
    const TYPE_SOURCE_SINK = 0x0400;

    /**
     * BIO_TYPE_START is the first user-allocated BIO type. No pre-defined type,
     * flag bits aside, may exceed this value.
     */
    const TYPE_START = 128;


    const FLAG_READ = 0x01;
    const FLAG_WRITE = 0x02;
    const FLAG_IO_SPECIAL = 0x04;
    const FLAG_RWS = self::FLAG_READ | self::FLAG_WRITE | self::FLAG_IO_SPECIAL;
    const FLAG_SHOULD_RETRY = 0x08;

    /**
     * Create new memory based BIO
     *
     * @return BIO
     */
    public static function new(): BIO
    {
        $ffi = OpenSSL::getFFI();
        $bio = $ffi->BIO_new($ffi->BIO_s_mem());
        return new BIO($ffi, $bio);
    }

    /**
     * Create new memory based BIO pre-filled with data
     *
     * @param string $data
     * @return BIO
     */
    public static function buffer(string $data): BIO
    {
        $ffi = OpenSSL::getFFI();
        $bio = $ffi->BIO_new_mem_buf($data, strlen($data));
        return new BIO($ffi, $bio);
    }

    /**
     * Create new file BIO with given mode
     *
     * @param string $fileName which file to open
     * @param string $mode mode to open file with see fopen(3)
     * @return BIO
     * @see fopen
     */
    public static function open(string $fileName, string $mode): BIO
    {
        $ffi = OpenSSL::getFFI();
        $bio = $ffi->BIO_new_file($fileName, $mode);
        return new BIO($ffi, $bio);
    }

    /**
     * @inheritDoc
     */
    protected function freeObject()
    {
        $this->ffi->BIO_free($this->cObj);
    }

    /**
     * Write given data to BIO, returns amount of bytes written
     *
     * @param string $data
     * @return int
     */
    function write(string $data): int
    {
        $len = $this->ffi->BIO_write($this->cObj, $data, strlen($data));
        if ($len === -2) {
            throw new RuntimeException("Can't wrote to this BIO");
        }

        if ($len === 0 || $len === -1) {
            if ($this->cObj->flags & self::FLAG_SHOULD_RETRY) {
                return $len;
            }

            throw new RuntimeException("Error occured while reading BIO");
        }

        return $len;
    }

    /**
     * Get type of BIO, indicating if this is e.g. a file see BIO::TYPE_* constants
     *
     * @return int
     */
    function getType(): int
    {
        return $this->ffi->BIO_method_type($this->cObj);
    }

    /**
     * Read from BIO
     *
     * @param int $chunkSize max amount of bytes to read in this operation
     * @return string
     */
    function read(int $chunkSize = 4096): string
    {
        $data = OpenSSL\C\Memory::new($chunkSize);
        $len = $this->ffi->BIO_read($this->cObj, $data->get(), $chunkSize);
        if ($len === -2) {
            throw new RuntimeException("Can't read from this BIO");
        }

        if ($len === 0 || $len === -1) {
            if ($this->cObj->flags & self::FLAG_SHOULD_RETRY) {
                return "";
            }

            throw new RuntimeException("Error occured while reading BIO");
        }

        return $data->string($len);
    }

    /**
     * Get location in file pointer, this only works with file BIO's
     *
     * @return int
     */
    function tell()
    {
        if (($this->getType() & self::TYPE_FILE) !== self::TYPE_FILE) {
            throw new RuntimeException("Can't tell on non-file BIO");
        }

        $pos = (int)$this->ctrl(self::C_FILE_TELL, 0, null);

        if ($pos === -1) {
            throw new RuntimeException("Failed to tell position in BIO");
        }

        return $pos;
    }

    /**
     * Reset position in BIO
     */
    function reset(): void
    {
        $res = (int)$this->ctrl(self::CTRL_RESET, 0, null);

        if (($this->getType() & self::TYPE_FILE) === self::TYPE_FILE && $res === 0) {
            return;
        }

        if ($res > 0) {
            return;
        }

        throw new RuntimeException("Failed to reset BIO");
    }

    /**
     * Seek in BIO, only works on file BIO's
     *
     * @param int $offset
     */
    function seek(int $offset)
    {
        if (($this->getType() & self::TYPE_FILE) !== self::TYPE_FILE) {
            throw new RuntimeException("Can't seek in non-file BIO");
        }

        $pos = (int)$this->ctrl(self::C_FILE_SEEK, $offset, null);

        if ($pos === -1) {
            throw new RuntimeException("Failed seeking in BIO");
        }
    }

    /**
     * returns true if we're at EOF of this BIO
     *
     * @return bool
     */
    function eof(): bool
    {
        return (int)$this->ctrl(self::CTRL_EOF, 0, null) === 1;
    }

    /**
     * Send control command to BIO
     *
     * @param int $prop
     * @param int $larg
     * @param mixed $parg
     * @return mixed
     */
    function ctrl(int $prop, int $larg = 0, $parg = null)
    {
        return $this->ffi->BIO_ctrl($this->cObj, $prop, $larg, $parg);
    }
}
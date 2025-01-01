# poodle-attack-sandbox

## Overview

This code is the test code for POODLE(CVE-2014-3566).

POODLE stands for "Padding Oracle On Downgraded Legacy Encryption" and is a vulnerability in SSLv3.0.

## Warning

If you use this code to carry out an attack, you may be arrested by the judicial authorities of your country.

Use for study purposes only.

## Installation

docker/docker compose が必要なのでインストールしてください。

1. コンテナ起動

```docker exec -it mitm-server bash
docker compose up
```

2. 中間者サーバーのスクリプト起動

- client<-->mitm<-->target の疎通確認ならば

    ```
    docker exec -it mitm-server bash
    ```

    コンテナ内で

    ```
    cd && cd mitm && sudo bash proxy-test.sh
    ```

- 攻撃用スクリプト起動ならば

    同様のコンテナ内で

    ```
    cd && cd mitm && sudo bash attack.sh
    ```

## Notice
mitmコンテナは中間者としてパケットの解析を行うために、iptablesを用いて一度パケットをキューに格納しています。

そのため上記のShell Scriptを実行しない場合、ご自身でデキューする処理を別プロセスで実行して頂かないとリクエストを送ったきりでレスポンスが帰ってきません。

ご注意ください。
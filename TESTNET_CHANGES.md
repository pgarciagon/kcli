# Cambios realizados en kcli

## Resumen

Se actualizo `kcli` para poder trabajar con la testnet oficial de Koinos Foundation, se agregaron comandos de transferencia, se subio la version a `1.3.0`, se compilo e instalo localmente, y se publico el cambio inicial en GitHub.

Repositorio remoto:

```txt
https://github.com/pgarciagon/kcli.git
```

Commit publicado:

```txt
a29358a Add official testnet support
```

## Soporte para testnet oficial

Se agrego soporte para redes nombradas:

```bash
kcli --network mainnet chain-info
kcli --network testnet chain-info
```

La testnet oficial queda configurada con:

```txt
JSON-RPC: https://testnet.koinosfoundation.org/jsonrpc
Health: https://testnet.koinosfoundation.org/health
Chain ID: EiAIKVvm6-V2qmsmUvPJy09vCCLbtn9lHFpwrJbcTIEWRQ==
KOIN: 1FaSvLjQJsCJKq5ybmGsMMQs8RQYyVv8ju
VHP: 17n12ktwN79sR6ia9DDgCfmw77EgpbTyBi
PoB: 1MAbK5pYkhp9yHnfhYamC3tfSLmVRTDjd9
Faucet: https://t.me/KoinosTestnetFaucetBot
```

## Comandos nuevos

Se agrego:

```bash
kcli testnet-info
kcli faucet-info
```

`testnet-info` muestra los datos oficiales de la testnet, incluyendo RPC, chain ID y contratos KOIN/VHP/PoB.

`faucet-info` muestra como pedir fondos al faucet de Telegram:

```txt
/faucet YOUR_KOINOS_ADDRESS
```

## Configuracion

Se agrego soporte para guardar red y RPC por defecto:

```bash
kcli config --network testnet
kcli config --rpc https://testnet.koinosfoundation.org/jsonrpc
kcli config --show
```

El orden de resolucion usado por `kcli` es:

1. Opcion de comando (`--network`, `--rpc`)
2. Configuracion guardada en `~/.kcli/config.json`
3. Valores por defecto de la red

## Contratos por red

Antes, `kcli` usaba contratos hardcodeados de mainnet. Ahora los comandos usan los contratos de la red seleccionada.

Esto afecta a:

```txt
balance
vhp
burn
register-producer-key
get-producer-key
producer-dashboard
```

Tambien se agrego una comprobacion de `chain_id` antes de firmar transacciones cuando la red tiene un chain ID conocido.

## Version

Se actualizo la version del proyecto:

```txt
1.1.0 -> 1.2.0 -> 1.3.0
```

Archivos actualizados:

```txt
package.json
package-lock.json
README.md
```

La version instalada localmente fue verificada con:

```bash
kcli --version
```

Resultado:

```txt
1.3.0
```

## Transferencias

Se agregaron comandos para transferir KOIN y tokens KCS-4:

```bash
kcli transfer <to> <amount>
kcli transfer <to> <amount> --dry-run
kcli token-transfer <contractId> <to> <amount>
kcli token-transfer <contractId> <to> <amount> --dry-run
```

Ejemplo en testnet:

```bash
kcli --network testnet transfer <to> 10
```

## Instalacion local

Se compilo e instalo localmente con:

```bash
npm install
npm run build
npm link
```

Tambien se corrigio un segundo enlace global viejo en Homebrew:

```txt
/opt/homebrew/bin/kcli
```

Ese enlace apuntaba a un checkout antiguo y seguia mostrando `1.1.0`. Se repunto al repo actual con:

```bash
npm_config_prefix=/opt/homebrew npm link
```

Despues de eso, ambos comandos reportaban `1.2.0`:

```txt
/opt/homebrew/bin/kcli --version
/Users/pgarcgo/.nvm/versions/node/v22.12.0/bin/kcli --version
kcli --version
```

## Verificaciones realizadas

Se verifico la compilacion:

```bash
npm run build
```

Se verifico la testnet:

```bash
kcli --network testnet chain-info
kcli --network testnet balance 1AvfaswZsCJ4FTaWDengYRj2y3aTnJ4oNo
kcli --network testnet vhp 1AvfaswZsCJ4FTaWDengYRj2y3aTnJ4oNo
kcli testnet-info
```

Tambien se genero una wallet de prueba y se comprobo que la direccion era valida en testnet:

```txt
1L2cMP9bhXDAjiSQwCT39QxXa8BwuCvA7H
```

Balance inicial en testnet:

```txt
KOIN: 0
VHP: 0
Mana: 0
```

## Faucet

Se comprobo que el faucet de Telegram acepta la peticion, pero fallo al enviar fondos por un problema del lado del faucet:

```txt
unable to consume rc for payer: 1AvfaswZsCJ4FTaWDengYRj2y3aTnJ4oNo
```

La direccion generada por `kcli` era valida; el problema parecia estar en la cuenta pagadora del bot o en su transaccion.

## Como ver productores en testnet

Para ver productores de testnet:

```bash
kcli --network testnet producer-dashboard
```

Opciones utiles:

```bash
kcli --network testnet producer-dashboard --window 240
kcli --network testnet producer-dashboard --window 500 --interval 3 --top 25
kcli --network testnet producer-dashboard --view peers
```

Dentro del dashboard:

```txt
1 = vista de productores
2 = vista de peers
q = salir
```

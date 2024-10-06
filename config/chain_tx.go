package config

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"
	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"
	"github.com/gagliardetto/solana-go/rpc"
	"github.com/hellodex/HelloSecurity/log"
	"github.com/hellodex/HelloSecurity/model"
	"github.com/hellodex/HelloSecurity/wallet/enc"
	"github.com/mr-tron/base58"
)

const maxRetries = 5

func (t ChainConfig) HandleMessage(message []byte, to string, typecode string, wg *model.WalletGenerated) (txhash string, sig []byte, err error) {
	if len(t.GetRpc()) == 0 {
		return txhash, sig, errors.New("rpc_config")
	}

	if wg.ChainCode == "SOLANA" {
		if typecode == "sign" {
			sig, err = enc.Porter().SigSol(wg.EncryptPK, message)
			if err != nil {
				log.Error("type=", typecode, err)
				return txhash, sig, err
			}
			return txhash, sig, err
		}
		c := rpc.New(t.GetRpc()[0])

		tx, _ := solana.TransactionFromDecoder(bin.NewBinDecoder(message))
		hashResult, err := c.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
		if err != nil {
			return txhash, sig, err
		}
		tx.Message.RecentBlockhash = hashResult.Value.Blockhash

		sig, err = enc.Porter().SigSol(wg.EncryptPK, message)
		if err != nil {
			return txhash, sig, err
		}
		tx.Signatures = []solana.Signature{solana.Signature(sig)}
		txhash, err := c.SendTransaction(context.Background(), tx)

		return base58.Encode(txhash[:]), sig, err
	} else { // for all evm
		if typecode == "sign" {
			sig, err = enc.Porter().SigEth(wg.EncryptPK, message)
			if err != nil {
				return txhash, sig, err
			}
			return txhash, sig, err
		}
		client, _ := ethclient.Dial(t.GetRpc()[0])

		nonce, err := client.PendingNonceAt(context.Background(), common.HexToAddress(wg.Wallet))
		if err != nil {
			return txhash, sig, err
		}

		gasPrice, err := client.SuggestGasPrice(context.Background())
		if err != nil {
			return txhash, sig, err
		}

		value := big.NewInt(0)
		gasLimit := uint64(300000)
		tx := types.NewTransaction(nonce, common.HexToAddress(to), value, gasLimit, gasPrice, message)

		// 查询链 ID
		chainID, err := client.NetworkID(context.Background())
		if err != nil {
			return txhash, sig, err
		}

		// 对交易进行签名
		signedTx, err := enc.Porter().SigEvmTx(wg.EncryptPK, tx, chainID)
		if err != nil {
			return txhash, sig, err
		}

		// 发送已签名的交易
		err = client.SendTransaction(context.Background(), signedTx)

		return signedTx.Hash().Hex(), sig, err
	}
}

func (t ChainConfig) HandlTransfer(to, mint string, amount *big.Int, wg *model.WalletGenerated) (txhash string, err error) {
	if len(t.GetRpc()) == 0 {
		return txhash, errors.New("rpc_config")
	}

	if wg.ChainCode == "SOLANA" {
		client := rpc.New(t.GetRpc()[0])
		fromAddr := solana.MustPublicKeyFromBase58(wg.Wallet)
		toAddr := solana.MustPublicKeyFromBase58(to)
		if mint == "" || mint == "SOL" {
			// SOL 主网币转账
			transaction := solana.Transaction{
				Message: solana.Message{
					Header: solana.MessageHeader{
						NumRequiredSignatures:       1,
						NumReadonlyUnsignedAccounts: 0,
						NumReadonlySignedAccounts:   0,
					},
					RecentBlockhash: solana.Hash{}, // 稍后将更新
				},
			}

			transaction.Message.AccountKeys = append(transaction.Message.AccountKeys, fromAddr, toAddr, solana.MustPublicKeyFromBase58("11111111111111111111111111111111"))

			// SOL 转账指令
			transferInstruction := system.NewTransferInstruction(
				amount.Uint64(),
				fromAddr,
				toAddr,
			)
			data := transferInstruction.Build()
			dData, _ := data.Data()
			compiledTransferInstruction := solana.CompiledInstruction{
				ProgramIDIndex: uint16(2), // 系统程序在 AccountKeys 中的索引，假设它是第6个
				Accounts: []uint16{
					0, // fromAddr 的索引
					1, // toAddr 的索引
				},
				Data: dData, // 编译指令的数据
			}
			transaction.Message.Instructions = append(transaction.Message.Instructions, compiledTransferInstruction)

			outHash, _ := client.GetLatestBlockhash(context.Background(), rpc.CommitmentFinalized)
			transaction.Message.RecentBlockhash = outHash.Value.Blockhash

			messageHash, _ := transaction.Message.MarshalBinary()
			sig, err := enc.Porter().SigSol(wg.EncryptPK, messageHash)
			if err != nil {
				return txhash, err
			}
			transaction.Signatures = []solana.Signature{solana.Signature(sig)}

			txbytes, _ := transaction.MarshalBinary()
			fmt.Println(base64.StdEncoding.EncodeToString(txbytes))

			txhash, err := client.SendTransaction(context.Background(), &transaction)
			return txhash.String(), err
		} else {
			fromAccount, _, _ := solana.FindAssociatedTokenAddress(fromAddr, solana.MustPublicKeyFromBase58(mint))
			toAccount, _, _ := solana.FindAssociatedTokenAddress(toAddr, solana.MustPublicKeyFromBase58(mint))

			transaction := solana.Transaction{
				Message: solana.Message{
					// 需要初始化头部信息
					Header: solana.MessageHeader{
						NumRequiredSignatures:       0, // 这稍后将更新
						NumReadonlyUnsignedAccounts: 0,
						NumReadonlySignedAccounts:   0,
					},
					RecentBlockhash: solana.Hash{}, // 这稍后将更新
				},
			}

			transaction.Message.AccountKeys = append(transaction.Message.AccountKeys,
				fromAddr, // 支付账户
				fromAccount,
				toAccount,                            // 要创建的 Token Account
				toAddr,                               // Token Account 所有者
				solana.MustPublicKeyFromBase58(mint), // Mint 地址
				solana.MustPublicKeyFromBase58("11111111111111111111111111111111"),            // 系统程序账户
				solana.MustPublicKeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), // 关联 Token 程序
			)
			toAccountInfo, _ := client.GetAccountInfo(context.Background(), toAccount)

			if toAccountInfo != nil {
				ownaddr := toAccountInfo.Value.Owner.String()
				fmt.Println(ownaddr)
			}

			if toAccountInfo == nil {
				transaction.Message.AccountKeys = append(
					transaction.Message.AccountKeys,
					solana.MustPublicKeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"),
				)
				createATAInstruction := associatedtokenaccount.NewCreateInstruction(
					transaction.Message.AccountKeys[0],
					toAddr,
					solana.MustPublicKeyFromBase58(mint),
				)
				data := createATAInstruction.Build()
				dData, _ := data.Data()

				compiledCreateAccountInstruction := solana.CompiledInstruction{
					ProgramIDIndex: uint16(7), // 假设 ATA 程序的索引为0
					// Accounts:       []int{0, (tokenAccountKeyIndex)}, // 使用创建指令的账户
					Accounts: []uint16{
						0,
						2,
						3,
						4,
						5,
						6,
					},
					Data: dData, // 编译的数据
				}
				transaction.Message.Instructions = append(transaction.Message.Instructions, compiledCreateAccountInstruction)
			}

			transferInstruction := token.NewTransferInstruction(
				amount.Uint64(),
				fromAccount,
				toAccount,
				fromAddr,
				nil,
			)
			data := transferInstruction.Build()
			dData, _ := data.Data()
			compiledTransferInstruction := solana.CompiledInstruction{
				ProgramIDIndex: uint16(6),
				Accounts: []uint16{
					1,
					2,
					0,
				},
				Data: dData, // 编译的数据
			}
			transaction.Message.Instructions = append(transaction.Message.Instructions, compiledTransferInstruction)

			transaction.Message.Header.NumRequiredSignatures = 1
			transaction.Message.Header.NumReadonlyUnsignedAccounts = 0
			transaction.Message.Header.NumReadonlySignedAccounts = 0

			acs := make([]string, 0)
			for _, v := range transaction.Message.AccountKeys {
				acs = append(acs, v.String())
			}
			log.Info(acs)

			// outHash, _ := client.GetLatestBlockhash(context.Background(), rpc.CommitmentProcessed)
			// transaction.Message.RecentBlockhash = outHash.Value.Blockhash

			// messageHash, _ := transaction.Message.MarshalBinary()

			// sig, err := enc.Porter().SigSol(wg.EncryptPK, messageHash)
			// if err != nil {
			// 	return txhash, err
			// }
			// transaction.Signatures = []solana.Signature{solana.Signature(sig)}

			// simuTx, err := client.SimulateTransaction(context.Background(), &transaction)
			// log.Info("simulate transaction: ", simuTx, err)
			// if err != nil {
			for retries := 0; retries < maxRetries; retries++ {
				outHash, err := client.GetLatestBlockhash(context.Background(), rpc.CommitmentProcessed)
				if err != nil {
					log.Errorf("Failed to get latest blockhash: %v", err)
					continue
				}
				// log.Infof("transaction retrying for : %d", retries)
				transaction.Message.RecentBlockhash = outHash.Value.Blockhash

				messageHash, _ := transaction.Message.MarshalBinary()
				sig, err := enc.Porter().SigSol(wg.EncryptPK, messageHash)
				if err != nil {
					return txhash, err
				}
				transaction.Signatures = []solana.Signature{solana.Signature(sig)}

				// 进行交易模拟
				simuTx, err := client.SimulateTransaction(context.Background(), &transaction)
				log.Infof("simulate transaction %d: ", retries, simuTx, err)

				// 如果模拟成功（err == nil），则退出重试循环
				if err == nil {
					break
				}

				if retries == maxRetries-1 {
					log.Errorf("Transaction simulation failed after %d attempts: %v", 5, err)
					return txhash, err
				}

				time.Sleep(500 * time.Millisecond)
			}
			// }

			txhash, err := client.SendTransaction(context.Background(), &transaction)
			if err != nil {
				return "", err
			}

			txbytes, _ := transaction.MarshalBinary()
			base64tx := base64.StdEncoding.EncodeToString(txbytes)
			log.Info("transaction data:", base64tx)

			return txhash.String(), err
		}
	}
	return txhash, errors.New("unsupport chain")

}

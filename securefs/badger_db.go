package securefs

import (
	cfg "strongbox/configuration"

	badger "github.com/dgraph-io/badger/v3"
	log "github.com/sirupsen/logrus"
)

var badgerInstance *BadgerDB

type BadgerDB struct {
	badger *badger.DB
}

func GetDBInstance() *BadgerDB {
	if badgerInstance == nil {
		badgerInstance = &BadgerDB{}
	}
	return badgerInstance
}

func (db *BadgerDB) InitDB() error {
	skey := cfg.Cfg.SecretKey
	opt := badger.DefaultOptions(cfg.Cfg.SecretPath)
	opt.EncryptionKey = skey
	opt.BlockCacheSize = 100 << 20
	opt.IndexCacheSize = 100 << 20

	var err error
	db.badger, err = badger.Open(opt)
	if err != nil {
		log.Error("open db error:", err)
	}

	return nil
}

func (db *BadgerDB) Set(key []byte, value []byte) error {
	txn := db.badger.NewTransaction(true)
	defer txn.Discard()

	err := txn.Set(key, value)
	if err != nil {
		log.Error("badger set error:", err)
		return err
	}

	if err := txn.Commit(); err != nil {
		log.Error("badger commit error:", err)
	}

	return nil
}

func (db *BadgerDB) Get(key []byte) ([]byte, error) {
	txn := db.badger.NewTransaction(false)
	item, err := txn.Get(key)
	if err == badger.ErrKeyNotFound {
		return []byte(""), nil
	}
	if err != nil {
		log.Print("badger get error:", err)
		return nil, err
	}

	var v []byte
	err = item.Value(func(val []byte) error {
		v = append(v, val...)
		return nil
	})
	if err != nil {
		log.Print("badger get error:", err)
		return nil, err
	}
	return v, nil
}

func (db *BadgerDB) Close() {
	db.badger.Close()
}

(ns clj-ejson.core
  (:require [cheshire.core :as json]
            [clojure.java.io :as io])
  (:import java.security.KeyPair
           java.security.Security
           javax.crypto.Cipher
           java.util.Base64
           org.bouncycastle.openssl.PEMParser
           org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(Security/addProvider (BouncyCastleProvider.))

(def ^:private encryption-regex #"(?m)^ENC\[(.*)\]\n*$")

(defn- to-keypair [pem-keypair]
  (let [p (JcaPEMKeyConverter.)]
    (.setProvider p "BC")
    (.getKeyPair p pem-keypair)))

(defn- decrypt [keypair s]
  (let [data (org.bouncycastle.cms.CMSEnvelopedData. (.decode (Base64/getDecoder) s))
        bytes (.getContent (first (.getRecipients (.getRecipientInfos data))) (org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient. (.getPrivate (to-keypair keypair))))]
    bytes
    ))

(defn- encrypt [keypair s]
  )

(defn- load-pem [filename]
  (with-open [reader (io/reader filename)]
    (.readObject (PEMParser. reader))))

(defn decrypt-file [ejson-file & options]
  (let [data (json/parse-string (slurp ejson-file))
        pem (load-pem (:private-key options))]
    (reduce-kv #(assoc %1 %2 (decrypt pem (encrypted-value %3))) {} data)))

(defn load-public-key [f])

(defn- encrypted-value [v]
  (second (re-find encryption-regex v)))

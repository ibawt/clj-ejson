(ns clj-ejson.core
  (:require [cheshire.core :as json]
            [clojure.java.io :as io])
  (:import java.security.KeyPair
           java.security.Security
           java.util.Base64
           org.bouncycastle.cms.CMSEnvelopedData
           org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
           org.bouncycastle.openssl.PEMParser
           org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(Security/addProvider (BouncyCastleProvider.))

(def ^:private encryption-regex #"(?m)^ENC\[(.*)\]\n*$")

(defn- to-keypair [pem-keypair]
  (let [p (JcaPEMKeyConverter.)]
    (.setProvider p "BC")
    (.getKeyPair p pem-keypair)))

(defn- decrypt-value [keypair s]
  (let [data (CMSEnvelopedData. (.decode (Base64/getDecoder) s))
        bytes (.getContent (first (.getRecipients (.getRecipientInfos data))) (JceKeyTransEnvelopedRecipient. (.getPrivate (to-keypair keypair))))]
    (String. bytes)))

(defn- encrypt [keypair s])

(defn- load-pem [pem]
  (with-open [r (io/reader pem)]
    (.readObject (PEMParser. r))))

(defn decrypt [m &{:keys [private-key]}]
  "Decrypts the values of the map"
  (let [pem (load-pem private-key)]
    (reduce-kv #(assoc %1 %2 (decrypt-value pem (encrypted-value %3))) {} m)))

(defn decrypt-file [ejson-file & rest]
  (with-open [s (io/reader ejson-file)]
    (apply decrypt (json/parse-stream s) rest)))

(defn- encrypted-value [v]
  (second (re-find encryption-regex v)))

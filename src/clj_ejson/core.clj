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

(defn- encrypted-value [v]
  (second (re-find encryption-regex v)))

(defn- to-keypair [pem-keypair]
  (->
   (JcaPEMKeyConverter.)
   (.setProvider "BC")
   (.getKeyPair pem-keypair)))

(defn- string->envelope [^String s]
  (->
   (Base64/getDecoder)
   (.decode s)
   (CMSEnvelopedData.)))

(defn- decrypt-value [env-recipient s]
  (->
   (string->envelope s)
   (.getRecipientInfos)
   (.getRecipients)
   (first)
   (.getContent env-recipient)
   (String.)))

(defn- load-pem [pem]
  (with-open [r (io/reader pem)]
    (.readObject (PEMParser. r))))

(defn- key->recipient [keypair]
  (JceKeyTransEnvelopedRecipient. (.getPrivate keypair)))

(defn decrypt-or-pass [r v]
  (let [vv (encrypted-value v)]
    (if vv
      (decrypt-value r vv)
      v)))

(defn decrypt [m &{:keys [private-key]}]
  "Decrypts the values of the map"
  (let [r (key->recipient (to-keypair (load-pem private-key)))
        f (fn [[k v]] (if (string? v)
                        [k (decrypt-or-pass r v)]
                        [k v]))]
    (clojure.walk/postwalk (fn [x] (if (map? x) (into {} (map f x)) x)) m)))

(defn decrypt-file [ejson-file & rest]
  "Decrypts with an implicit open and read"
  (with-open [s (io/reader ejson-file)]
    (apply decrypt (json/parse-stream s) rest)))

(defn encrypt [m &{:keys [public-key]}])

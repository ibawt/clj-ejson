(ns clj-ejson.core
  (:require [cheshire.core :refer [parse-stream]]
            [clojure.java.io :as io]
            [clojure.walk :refer [postwalk]])
  (:import java.security.Security
           java.util.Base64
           org.bouncycastle.cms.CMSProcessableByteArray
           org.bouncycastle.cms.CMSEnvelopedDataGenerator
           org.bouncycastle.cms.CMSEnvelopedData
           org.bouncycastle.cms.CMSAlgorithm
           org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
           org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
           org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
           org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
           org.bouncycastle.openssl.PEMParser
           org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
           org.bouncycastle.jce.provider.BouncyCastleProvider))

(Security/addProvider (BouncyCastleProvider.))

(defn- encrypted-value [v]
  "grabs the encrypted payload from v"
  (second (re-find #"(?m)^ENC\[(.*)\]\n*$" v)))

(defn- to-keypair [pem-keypair]
  "converts an openssl keypair into a jcajce"
  (->
   (JcaPEMKeyConverter.)
   (.setProvider "BC")
   (.getKeyPair pem-keypair)))

(defn- string->envelope [s]
  "base64 decodes s and constructs a CMSEnvelopedData around it"
  (->
   (Base64/getDecoder)
   (.decode s)
   (CMSEnvelopedData.)))

(defn- decrypt-value [env-recipient s]
  "decrypt s with env-recipient"
  (->
   (string->envelope s)
   (.. (getRecipientInfos) (getRecipients))
   (first)
   (.getContent env-recipient)
   (String.)))

(defn- load-pem [pem]
  "read a PEMKeypair from pem"
  (with-open [r (io/reader pem)]
    (.readObject (PEMParser. r))))

(defn- key->recipient [keypair]
  "construct a recipient from the keypair"
  (JceKeyTransEnvelopedRecipient. (.getPrivate keypair)))

(defn- decrypt-or-pass [r v]
  "decrypt v with r if v is a valid ejson value
   or return it's normal value"
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
    (postwalk (fn [x] (if (map? x) (into {} (map f x)) x)) m)))

(defn decrypt-file [ejson-file & rest]
  "Decrypts with an implicit open and read"
  (with-open [s (io/reader ejson-file)]
    (apply decrypt (parse-stream s) rest)))

(defn- encrypt-recipient [pem]
  (let [cert (.getCertificate (.setProvider (JcaX509CertificateConverter.) "BC") pem)]
    (.setProvider (JceKeyTransRecipientInfoGenerator. cert) "BC")))

(def ^:private encryptor
  (->
   (JceCMSContentEncryptorBuilder. CMSAlgorithm/AES256_CBC)
   (.setProvider "BC")
   (.build)))

(defn- encrypt-value [r v]
  (let [data (CMSProcessableByteArray. (.getBytes v))
        ed-gen (CMSEnvelopedDataGenerator.)]
    (.addRecipientInfoGenerator ed-gen r)
    (.encodeToString (Base64/getEncoder) (.getEncoded (.generate ed-gen data encryptor)))))

(defn encrypt [m &{:keys [public-key]}]
  (let [r (encrypt-recipient (load-pem public-key))
        f (fn [[k v]] (if (and (string? v) (not (.startsWith k "_")) (nil? (encrypted-value v)) )
                        [k (str "ENC[" (encrypt-value r v) "]")]
                        [k v]))]
    (postwalk (fn [x] (if (map? x) (into {} (map f x)) x)) m)))

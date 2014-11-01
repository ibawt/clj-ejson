(ns clj-ejson.core
  (:require [cheshire.core :as json]
            [clojure.java.io :as io]))

(def ^:private encryption-regex #"(?m)^ENC\[(.*)\]\n*$")

(defn- decrypt [s])

(defn- encrypt [s])

(defn load-private-key [f])

(defn load-public-key [f])

(defn- encrypted-value [v]
  (second (re-find encryption-regex v)))

(defn- )

(defn load-file [path]
  (with-open [in (io/reader (io/file path))]
    (->
     (json/parse-stream in)
     ;(decode-keys)
     )))

(defn write-file [c path]
  )

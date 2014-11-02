(ns clj-ejson.core-test
  (:require [clojure.test :refer :all]
            [clj-ejson.core :refer :all]))

(def nested-test
  {"level1"
   {"level2"
    {"foo" "bar"}
    "bar" "foo"}
   "root" "beer"})

(def nested-enc-map
  (cheshire.core/parse-string (slurp "test/fixtures/nested_test.ejson")))

(def simple-enc-map
  (cheshire.core/parse-string (slurp "test/fixtures/test.ejson")))

(def priv-key "test/fixtures/privatekey.pem")

(def pub-key "test/fixtures/publickey.pem")

(deftest decryption-test
  (testing "basic decryption with a known value"
    (is (= {"foo" "bar"}
           (decrypt-file "test/fixtures/test.ejson" :private-key priv-key))))

  (testing "nested values"
    (is (= nested-test
           (decrypt-file "test/fixtures/nested_test.ejson"
                         :private-key priv-key))))

  (testing "should leave unencrypted fields alone"
    (let [enc-map (merge nested-enc-map {"boo" "baz"})]
      (is (= (merge nested-test {"boo" "baz"})
             (decrypt enc-map :private-key priv-key)))))

  (testing "should throw an exception when the key doesnt match"
    (is (thrown? Exception
                 (decrypt (merge nested-enc-map {"foo" "ENC[dfkdsfdsfds]"}) :private-key priv-key)))))

(deftest encryption-test
  (testing "basic encryption of values"
    (is (= {"foo" "bar"}
           (decrypt (encrypt {"foo" "bar"} :public-key pub-key) :private-key priv-key))))

  (testing "nested values"
    (is (= nested-test
           (decrypt (encrypt nested-test :public-key pub-key) :private-key priv-key))))

  (testing "should only encrypt unencrypted keys"
    (let [enc (encrypt {"foo" "bar"} :public-key pub-key)
          enc-new (encrypt (merge enc {"bar" "baz"}) :public-key pub-key)]
      (is (= enc (dissoc enc-new "bar")))))

  (testing "rencrypting is a noop"
    (let [enc (encrypt {"foo" "bar"} :public-key pub-key)]
      (is (= enc (encrypt enc :public-key pub-key)))))

  (testing "should ignore fields that start with an _"
    (is (= "field" (get (encrypt {"foo" "bar" "_private" "field"} :public-key pub-key) "_private")))))

(deftest end-to-end-test
  (testing "encrypt->decrypt"
    (is (= nested-test (decrypt (encrypt nested-test :public-key pub-key)
                                :private-key priv-key)))))

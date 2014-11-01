(ns clj-ejson.core-test
  (:require [clojure.test :refer :all]
            [clj-ejson.core :refer :all]))

(deftest decryption
  (testing "basic decryption with a known value"
    (is (= {"foo" "bar"}
           (decrypt-file "test/fixtures/test.ejson" :private-key "test/fixtures/privatekey.pem")))))

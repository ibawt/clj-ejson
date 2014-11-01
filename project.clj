(defproject clj-ejson "0.1.0-SNAPSHOT"
  :description "Clojure version of https://github.com/Shopify/ejson"
  :url "https://github.com/ibawt/clj-ejson"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.bouncycastle/bcprov-jdk15on "1.51"]
                 [org.bouncycastle/bcpkix-jdk15on "1.51"]
                 [cheshire "5.3.1"]]
  :plugins [[cider/cider-nrepl "0.8.0-SNAPSHOT"]])

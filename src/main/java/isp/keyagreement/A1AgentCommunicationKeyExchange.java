package isp.keyagreement;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Implement the unauthenticated key exchange from the slides between Alice and Bob using
 * public-key encryption to establish a shared symmetric secret (not DH or ECDH alone).
 * Then Alice sends Bob a message encrypted with AES-GCM. Bob decrypts and displays it.
 * The public key is not authenticated, so the exchange is vulnerable to active attackers.
 */
public class A1AgentCommunicationKeyExchange {
    public static void main(String[] args) {
        final Environment env = new Environment();

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {

            }
        });

        env.add(new Agent("bob") {
            @Override
            public void task() throws Exception {

            }
        });

        env.connect("alice", "bob");
        env.start();
    }
}

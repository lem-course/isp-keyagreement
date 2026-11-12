package isp.signatures;

import fri.isp.Agent;
import fri.isp.Environment;

/*
 * Assuming Alice and Bob know each other's authentic public key, exchange signed messages
 * using ECDSA. Complete ten request-reply rounds: Alice sends a signed message and Bob
 * sends a signed reply in each round. Each recipient verifies the signature and rejects
 * invalid messages. Signatures provide integrity and evidence of the signer, not secrecy.
 */
public class A2AgentCommunicationSignature {
    public static void main(String[] args) {
        final Environment env = new Environment();

        // Create key pairs

        env.add(new Agent("alice") {
            @Override
            public void task() throws Exception {
                // create a message, sign it,
                // and send the message, signature pair to bob
                // receive the message-signature pair, verify the signature
                // repeat 10 times
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

package dk.magenta.mox.moxtabel;

import dk.magenta.mox.agent.AmqpDefinition;
import dk.magenta.mox.agent.MessageReceiver;
import dk.magenta.mox.agent.MessageSender;
import dk.magenta.mox.agent.MoxAgent;
import org.apache.log4j.Logger;
import org.apache.log4j.xml.DOMConfigurator;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Created by lars on 25-01-16.
 */
public class MoxTabel extends MoxAgent {

    private final URL restInterface;
    private AmqpDefinition listenerDefinition;
    private AmqpDefinition senderDefinition;
    private Logger log = Logger.getLogger(MoxTabel.class);

    public static void main(String[] args) {
        DOMConfigurator.configure("log4j.xml");
        MoxTabel agent = new MoxTabel(args);
        agent.run();
    }

    public MoxTabel(String[] args) {
        super(args);

        String listenerPrefix = "amqp.incoming";
        String senderPrefix = "amqp.outgoing";

        this.listenerDefinition = new AmqpDefinition();
        this.listenerDefinition.populateFromMap(this.commandLineArgs, listenerPrefix, true, true);
        this.listenerDefinition.populateFromProperties(this.properties, listenerPrefix, false);
        this.listenerDefinition.populateFromDefaults(true, listenerPrefix);

        this.senderDefinition = new AmqpDefinition();
        this.senderDefinition.populateFromMap(this.commandLineArgs, senderPrefix, true, true);
        this.senderDefinition.populateFromProperties(this.properties, senderPrefix, false);
        this.senderDefinition.populateFromDefaults(true, senderPrefix);


        try {
            this.restInterface = new URL(this.getSetting("rest.interface"));
        } catch (MalformedURLException e) {
            throw new RuntimeException("Rest interface URL is malformed", e);
        }

        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                MoxTabel.this.shutdown();
            }
        });
    }

    protected String getDefaultPropertiesFileName() {
        return "moxtabel.properties";
    }

    @Override
    public void run() {
        log.info("\n--------------------------------------------------------------------------------");
        log.info("MoxTabel Starting");
        log.info("Listening for messages from RabbitMQ service at " + this.listenerDefinition.getAmqpLocation() + ", queue name '" + this.listenerDefinition.getQueueName() + "'");
        log.info("Successfully converted messages will be forwarded to the RabbitMQ service at " + this.senderDefinition.getAmqpLocation() + ", queue name '"+this.senderDefinition.getQueueName()+"'");
        MessageReceiver messageReceiver = null;
        MessageSender messageSender = null;
        try {
            log.info("Creating MessageReceiver instance");
            messageReceiver = new MessageReceiver(this.listenerDefinition, true);
            log.info("Creating MessageSender instance");
            messageSender = new MessageSender(this.senderDefinition);
            log.info("Running MessageReceiver instance");
            messageReceiver.run(new UploadedDocumentMessageHandler(messageSender, restInterface));
            log.info("MessageReceiver instance stopped on its own");
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        log.info("MoxTabel Shutting down");
        if (messageReceiver != null) {
            messageReceiver.close();
        }
        if (messageSender != null) {
            messageSender.close();
        }
        log.info("--------------------------------------------------------------------------------\n");
    }

    protected void shutdown() {
        this.log.info("Received SIGINT");
        this.log.info("MoxTabel shutting down");
        log.info("--------------------------------------------------------------------------------\n");
    }

}

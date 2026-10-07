import { startupFailureMessage } from '../config.ts';
import { startFlowDemo } from './flow-server.ts';

try {
  const demo = await startFlowDemo();
  console.log(`Flowseite: http://127.0.0.1:${demo.port}`);
  const shutdown = (signal: string): void => {
    console.log(`${signal} – Flow-Demo wird beendet.`);
    demo.flowServer.close();
    demo.apiServer.close();
    // Ohne das blieben der OCSP-Responder und der Trust-List-Server aus der
    // TEST-Umgebung weiterlaufen und der Prozess beendete sich nicht.
    void demo.env.close().finally(() => process.exit(0));
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
} catch (error) {
  console.error(startupFailureMessage(error));
  process.exit(1);
}

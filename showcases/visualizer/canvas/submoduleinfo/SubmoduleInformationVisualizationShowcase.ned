package inet.showcases.visualizer.canvas.submoduleinfo;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211RadioMedium;
import inet.visualizer.canvas.integrated.IntegratedCanvasVisualizer;


network SubmoduleInformationVisualizationShowcase
{
    submodules:
        visualizer: IntegratedCanvasVisualizer {
            @display("p=100,100");
        }
        configurator: Ipv4NetworkConfigurator {
            @display("p=100,200");
        }
        radioMedium: Ieee80211RadioMedium {
            @display("p=100,300");
        }
        source: AdhocHost {
            @display("p=300,200");
        }
        destination: AdhocHost {
            @display("p=600,200");
        }
        relay: AdhocHost {
            @display("p=447,143");
        }
}

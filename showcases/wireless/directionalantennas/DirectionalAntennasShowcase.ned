package inet.showcases.wireless.directionalantennas;

import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.node.inet.AdhocHost;
import inet.physicallayer.wireless.ieee80211.packetlevel.Ieee80211RadioMedium;
import inet.visualizer.canvas.integrated.IntegratedCanvasVisualizer;


network DirectionalAntennasShowcase
{
    @display("bgb=700,400");
    @statistic[receptionPower](source="receptionMinSignalPower(radioMedium.signalArrivalStarted)"; record=vector);
    submodules:
        configurator: Ipv4NetworkConfigurator {
            @display("p=62,43;is=s");
        }
        visualizer: IntegratedCanvasVisualizer {
            @display("p=62,121;is=s");
        }
        radioMedium: Ieee80211RadioMedium {
            @display("p=62,199;is=s");
        }
        source: AdhocHost {
            @display("p=400,200");
        }
        destination: AdhocHost {
            @display("p=400,350");
        }
}

import { Switch, Route, Router as WouterRouter } from "wouter";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Layout } from "@/components/layout";
import DashboardPage from "@/pages/dashboard";
import MandatesPage from "@/pages/mandates";
import MandateDetailPage from "@/pages/mandate-detail";
import CredentialsPage from "@/pages/credentials";
import ProfilesPage from "@/pages/profiles";
import PoaMapPage from "@/pages/poa-map";
import NotFound from "@/pages/not-found";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});

function Router() {
  return (
    <Layout>
      <Switch>
        <Route path="/" component={DashboardPage} />
        <Route path="/mandates" component={MandatesPage} />
        <Route path="/mandates/:id" component={MandateDetailPage} />
        <Route path="/credentials" component={CredentialsPage} />
        <Route path="/profiles" component={ProfilesPage} />
        <Route path="/poa-map" component={PoaMapPage} />
        <Route component={NotFound} />
      </Switch>
    </Layout>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, "")}>
          <Router />
        </WouterRouter>
        <Toaster />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;

import { Link } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex items-center justify-center py-20">
      <Card className="w-full max-w-md">
        <CardContent className="pt-6 text-center space-y-4">
          <div className="text-6xl font-bold text-primary/20">404</div>
          <h1 className="text-xl font-semibold">Page Not Found</h1>
          <p className="text-sm text-muted-foreground">
            The page you're looking for doesn't exist or has been moved.
          </p>
          <Link href="/">
            <Button variant="default">Return to Dashboard</Button>
          </Link>
        </CardContent>
      </Card>
    </div>
  );
}

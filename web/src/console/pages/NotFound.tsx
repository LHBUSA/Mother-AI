import { Link } from "../lib/router";
import { Empty } from "../components/ui";

export function NotFoundPage() {
  return (
    <Empty title="This page doesn't exist" action={<Link to="/app/" className="btn btn-secondary">Back to overview</Link>}>
      The console route you opened isn't part of the control plane.
    </Empty>
  );
}

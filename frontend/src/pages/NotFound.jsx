import { Link } from "react-router";

export function NotFound() {
  return (
    <div className="page">
      <div className="page__header">
        <h1>Page not found</h1>
      </div>
      <p className="notice">
        This address does not match any page. Go to the <Link to="/">overview</Link>.
      </p>
    </div>
  );
}

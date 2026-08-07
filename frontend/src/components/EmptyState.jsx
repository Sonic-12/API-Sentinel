import { Inbox } from "lucide-react";

export default function EmptyState({ icon: Icon = Inbox, message }) {
  return (
    <div className="empty">
      <Icon strokeWidth={1.5} />
      <p>{message}</p>
    </div>
  );
}
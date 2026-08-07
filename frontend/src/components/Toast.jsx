import { useEffect, useState } from "react";
import { ShieldAlert, X } from "lucide-react";

/**
 * Stack of transient toast notifications. `toasts` is [{ id, title, body }];
 * caller owns the array and passes a dismiss handler -- keeps this component
 * a pure renderer instead of managing its own timers-vs-state race.
 */
export default function ToastStack({ toasts, onDismiss }) {
  if (!toasts.length) return null;
  return (
    <div className="toast-stack">
      {toasts.map((t) => (
        <ToastItem key={t.id} toast={t} onDismiss={() => onDismiss(t.id)} />
      ))}
    </div>
  );
}

function ToastItem({ toast, onDismiss }) {
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    const leaveTimer = setTimeout(() => setLeaving(true), 5200);
    const removeTimer = setTimeout(onDismiss, 5600);
    return () => {
      clearTimeout(leaveTimer);
      clearTimeout(removeTimer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className={`toast toast-high${leaving ? " leaving" : ""}`}>
      <ShieldAlert strokeWidth={2} />
      <div className="toast-body">
        <p className="toast-title">{toast.title}</p>
        <p className="toast-sub">{toast.body}</p>
      </div>
      <button className="toast-close" onClick={onDismiss} aria-label="Dismiss">
        <X size={14} strokeWidth={2} />
      </button>
    </div>
  );
}

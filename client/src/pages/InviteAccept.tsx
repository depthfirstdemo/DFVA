import type { ReactNode } from "react";
import { useRoute, useLocation } from "wouter";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { useSession } from "@/lib/session";
import { Shield, CheckCircle, UserPlus, Eye, BarChart2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";

const ROLE_COLORS: Record<string, string> = {
  admin: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  analyst: "text-primary bg-primary/10 border-primary/30",
  viewer: "text-muted-foreground bg-muted/40 border-border",
};

const ROLE_ICONS: Record<string, ReactNode> = {
  admin: <Shield className="w-4 h-4" />,
  analyst: <BarChart2 className="w-4 h-4" />,
  viewer: <Eye className="w-4 h-4" />,
};

export default function InviteAccept() {
  const [, params] = useRoute("/invite/:token");
  const [, navigate] = useLocation();
  const { user } = useSession();
  const { toast } = useToast();

  const token = params?.token ?? "";

  const { data: invitation, isLoading, error } = useQuery<any>({
    queryKey: ["/api/invitations", token],
    queryFn: () => fetch(`/api/invitations/${token}`).then(r => r.json()),
    enabled: !!token,
    retry: false,
  });

  const invitationRole = invitation?.role ?? "viewer";

  const accept = useMutation({
    mutationFn: () =>
      apiRequest("POST", `/api/invitations/${token}/accept`, { userId: user?.id }),
    onSuccess: (data: any) => {
      toast({
        title: `Joined as ${data.message?.split("as ")[1] ?? invitationRole}`,
        description: `You now have ${invitationRole} access to the workspace.`,
      });
      navigate("/workspaces");
    },
    onError: (e: any) => {
      toast({ title: "Error", description: e.message, variant: "destructive" });
    },
  });

  return (
    <div className="min-h-[80vh] flex items-center justify-center px-4">
      <div className="w-full max-w-md space-y-6">
        {/* Header */}
        <div className="text-center">
          <div className="w-14 h-14 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center mx-auto mb-4">
            <UserPlus className="w-7 h-7 text-primary" />
          </div>
          <h1 className="text-2xl font-display font-bold">Workspace Invitation</h1>
          <p className="text-muted-foreground text-sm mt-1">You've been invited to join a team workspace</p>
        </div>

        {isLoading && (
          <div className="rounded-xl border border-border/60 bg-card/40 p-6 text-center text-sm text-muted-foreground">
            Loading invitation…
          </div>
        )}

        {!isLoading && (error || invitation?.message) && (
          <div className="rounded-xl border border-destructive/40 bg-destructive/5 p-6 text-center">
            <p className="text-destructive text-sm font-medium">Invitation not found or already accepted.</p>
          </div>
        )}

        {!isLoading && invitation && !invitation.message && (
          <>
            {/* Invitation details card */}
            <div className="rounded-xl border border-border/60 bg-card/40 p-5 space-y-4">
              <div>
                <div className="text-xs text-muted-foreground mb-1">Workspace</div>
                <div className="font-semibold">{invitation.workspaceName ?? `Workspace #${invitation.workspaceId}`}</div>
              </div>

              <div>
                <div className="text-xs text-muted-foreground mb-1">Invited email</div>
                <div className="text-sm font-mono">{invitation.email}</div>
              </div>

              <div>
                <div className="text-xs text-muted-foreground mb-2">Role on acceptance</div>
                <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-lg border ${ROLE_COLORS[invitationRole] ?? ROLE_COLORS.viewer}`}>
                  {ROLE_ICONS[invitationRole] ?? ROLE_ICONS.viewer} {invitationRole}
                </span>
              </div>
            </div>

            {/* Token weakness note */}
            <div className="rounded-lg border border-border/40 bg-muted/10 p-3">
              <div className="text-[10px] text-muted-foreground mb-1 font-semibold uppercase tracking-wide">Token weakness</div>
              <code className="text-[10px] font-mono text-muted-foreground break-all">{token}</code>
              <div className="text-[10px] text-muted-foreground mt-1.5">
                Generated with <code className="font-mono">Math.random().toString(36)</code> — same weak randomness as VULN #13. Brute-forceable to discover all pending invitations.
              </div>
            </div>

            {/* Accept button */}
            {!invitation.acceptedAt ? (
              user ? (
                <Button
                  data-testid="button-accept-invite"
                  className="w-full"
                  onClick={() => accept.mutate()}
                  disabled={accept.isPending}
                >
                  {accept.isPending ? "Joining…" : (
                    <>
                      <CheckCircle className="w-4 h-4 mr-2" />
                      Accept — Join as {invitationRole}
                    </>
                  )}
                </Button>
              ) : (
                <div className="space-y-2">
                  <p className="text-sm text-muted-foreground text-center">Sign in to accept this invitation</p>
                  <Button className="w-full" onClick={() => navigate("/login")}>Sign In</Button>
                </div>
              )
            ) : (
              <div className="rounded-xl border border-primary/20 bg-primary/5 p-4 text-center">
                <CheckCircle className="w-5 h-5 text-primary mx-auto mb-1" />
                <p className="text-sm font-medium">Invitation already accepted</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

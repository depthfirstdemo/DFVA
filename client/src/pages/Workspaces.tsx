import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useSession } from "@/lib/session";
import { useLocation } from "wouter";
import { Building2, Users, Mail, Shield, Eye, BarChart2, Plus, Trash2, ChevronRight, Copy, AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const ROLE_ICONS: Record<string, React.ReactNode> = {
  admin: <Shield className="w-3 h-3" />,
  analyst: <BarChart2 className="w-3 h-3" />,
  viewer: <Eye className="w-3 h-3" />,
};

const ROLE_COLORS: Record<string, string> = {
  admin: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  analyst: "bg-primary/15 text-primary border-primary/30",
  viewer: "bg-muted/60 text-muted-foreground border-border",
};

type Workspace = { id: number; name: string; ownerId: number; createdAt: string };
type Member = { id: number; workspaceId: number; userId: number; role: string; joinedAt: string; username: string; email: string | null };
type Invitation = { id: number; workspaceId: number; email: string; role: string; token: string; createdAt: string; acceptedAt: string | null };

export default function Workspaces() {
  const { user } = useSession();
  const [, navigate] = useLocation();
  const { toast } = useToast();

  const [newName, setNewName] = useState("");
  const [selectedWs, setSelectedWs] = useState<Workspace | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("viewer");
  const [viewAsUserId, setViewAsUserId] = useState(user?.id?.toString() ?? "");

  const { data: workspaces = [], isLoading } = useQuery<Workspace[]>({
    queryKey: ["/api/workspaces", viewAsUserId],
    queryFn: () => fetch(`/api/workspaces?userId=${viewAsUserId}`).then(r => r.json()),
    enabled: !!viewAsUserId,
  });

  const { data: members = [] } = useQuery<Member[]>({
    queryKey: ["/api/workspaces", selectedWs?.id, "members"],
    queryFn: () => fetch(`/api/workspaces/${selectedWs!.id}/members`).then(r => r.json()),
    enabled: !!selectedWs,
  });

  const { data: scans = [] } = useQuery<any[]>({
    queryKey: ["/api/workspaces", selectedWs?.id, "scans"],
    queryFn: () => apiRequest("GET", `/api/workspaces/${selectedWs!.id}/scans`).then(r => r.json()),
    enabled: !!selectedWs,
  });

  const { data: invitations = [] } = useQuery<Invitation[]>({
    queryKey: ["/api/workspaces", selectedWs?.id, "invitations"],
    queryFn: () => fetch(`/api/workspaces/${selectedWs!.id}/invitations`).then(r => r.json()),
    enabled: !!selectedWs,
  });

  const createWs = useMutation({
    mutationFn: (name: string) => apiRequest("POST", "/api/workspaces", { name, ownerId: user?.id }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces", viewAsUserId] });
      setNewName("");
      toast({ title: "Workspace created" });
    },
  });

  const inviteMember = useMutation({
    mutationFn: ({ email, role }: { email: string; role: string }) =>
      apiRequest("POST", `/api/workspaces/${selectedWs!.id}/invite`, { email, role }),
    onSuccess: (data: any) => {
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces", selectedWs?.id, "invitations"] });
      setInviteEmail("");
      toast({
        title: "Invitation sent",
        description: `Link: ${data.inviteUrl}`,
      });
    },
  });

  const changeRole = useMutation({
    mutationFn: ({ memberId, role }: { memberId: number; role: string }) =>
      apiRequest("PATCH", `/api/workspaces/${selectedWs!.id}/members/${memberId}`, { role }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces", selectedWs?.id, "members"] });
      toast({ title: "Role updated" });
    },
  });

  const removeMember = useMutation({
    mutationFn: (memberId: number) =>
      apiRequest("DELETE", `/api/workspaces/${selectedWs!.id}/members/${memberId}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/workspaces", selectedWs?.id, "members"] });
      toast({ title: "Member removed" });
    },
  });

  if (!user) {
    return (
      <div className="min-h-[60vh] flex items-center justify-center">
        <div className="text-center">
          <Building2 className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
          <p className="text-muted-foreground mb-4">Sign in to manage workspaces</p>
          <Button onClick={() => navigate("/login")}>Sign In</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
      <div className="mb-8">
        <h1 className="text-3xl font-display font-bold mb-1">Team Workspaces</h1>
        <p className="text-muted-foreground text-sm">Create workspaces, invite members, and share scans across your team.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left — Workspace list + create */}
        <div className="space-y-4">
          {/* IDOR demo banner */}
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 flex gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <div className="text-xs text-amber-300/80">
              <span className="font-semibold text-amber-400">IDOR demo:</span> change the user ID below to enumerate any user's workspaces — no ownership check.
            </div>
          </div>

          <div className="flex gap-2">
            <Input
              data-testid="input-view-user-id"
              placeholder="View as userId"
              value={viewAsUserId}
              onChange={e => setViewAsUserId(e.target.value)}
              className="h-8 text-xs font-mono bg-muted/30"
            />
            <Button
              data-testid="button-view-workspaces"
              size="sm"
              variant="outline"
              onClick={() => queryClient.invalidateQueries({ queryKey: ["/api/workspaces", viewAsUserId] })}
            >
              Go
            </Button>
          </div>

          {/* Create new */}
          <div className="rounded-lg border border-border/60 bg-card/40 p-4 space-y-3">
            <h3 className="text-sm font-semibold">New Workspace</h3>
            <Input
              data-testid="input-workspace-name"
              placeholder="e.g. Red Team Alpha"
              value={newName}
              onChange={e => setNewName(e.target.value)}
            />
            <Button
              data-testid="button-create-workspace"
              className="w-full"
              size="sm"
              disabled={!newName.trim() || createWs.isPending}
              onClick={() => createWs.mutate(newName.trim())}
            >
              <Plus className="w-3 h-3 mr-1" /> Create
            </Button>
          </div>

          {/* List */}
          {isLoading ? (
            <div className="text-sm text-muted-foreground">Loading…</div>
          ) : workspaces.length === 0 ? (
            <div className="text-sm text-muted-foreground rounded-lg border border-dashed border-border/60 p-6 text-center">
              No workspaces found for user {viewAsUserId}
            </div>
          ) : (
            <div className="space-y-2">
              {workspaces.map(ws => (
                <button
                  key={ws.id}
                  data-testid={`card-workspace-${ws.id}`}
                  onClick={() => setSelectedWs(ws)}
                  className={`w-full text-left rounded-lg border p-3 transition-all ${
                    selectedWs?.id === ws.id
                      ? "border-primary/60 bg-primary/5"
                      : "border-border/60 bg-card/40 hover:border-border"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Building2 className="w-4 h-4 text-primary" />
                      <span className="text-sm font-medium">{ws.name}</span>
                    </div>
                    <ChevronRight className="w-3 h-3 text-muted-foreground" />
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">ID: {ws.id} · owner: {ws.ownerId}</div>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Right — Workspace detail */}
        {selectedWs ? (
          <div className="lg:col-span-2 space-y-6">
            <div className="rounded-lg border border-border/60 bg-card/40 p-5">
              <h2 className="text-lg font-semibold mb-1 flex items-center gap-2">
                <Building2 className="w-5 h-5 text-primary" />
                {selectedWs.name}
              </h2>
              <p className="text-xs text-muted-foreground">Workspace ID: {selectedWs.id}</p>
            </div>

            {/* Members */}
            <div className="rounded-lg border border-border/60 bg-card/40 p-5 space-y-4">
              <div className="flex items-center gap-2 mb-1">
                <Users className="w-4 h-4 text-primary" />
                <h3 className="font-semibold text-sm">Members</h3>
                <div className="ml-auto">
                  <div className="flex items-center gap-1 text-xs text-amber-400/80 bg-amber-500/5 border border-amber-500/20 rounded px-2 py-0.5">
                    <AlertTriangle className="w-3 h-3" />
                    No role check on PATCH/DELETE
                  </div>
                </div>
              </div>

              {members.length === 0 ? (
                <p className="text-xs text-muted-foreground">No members yet.</p>
              ) : (
                <div className="space-y-2">
                  {members.map(m => (
                    <div
                      key={m.id}
                      data-testid={`row-member-${m.id}`}
                      className="flex items-center gap-3 rounded-lg bg-muted/20 px-3 py-2"
                    >
                      <div className="w-7 h-7 rounded-full bg-primary/20 text-primary text-xs font-bold flex items-center justify-center uppercase">
                        {m.username[0]}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{m.username}</div>
                        <div className="text-xs text-muted-foreground font-mono">uid:{m.userId}</div>
                      </div>
                      <Select
                        value={m.role}
                        onValueChange={role => changeRole.mutate({ memberId: m.id, role })}
                      >
                        <SelectTrigger data-testid={`select-role-${m.id}`} className="w-28 h-7 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="viewer">Viewer</SelectItem>
                          <SelectItem value="analyst">Analyst</SelectItem>
                          <SelectItem value="admin">Admin</SelectItem>
                        </SelectContent>
                      </Select>
                      <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${ROLE_COLORS[m.role]}`}>
                        {ROLE_ICONS[m.role]} {m.role}
                      </span>
                      <button
                        data-testid={`button-remove-member-${m.id}`}
                        onClick={() => removeMember.mutate(m.id)}
                        className="text-muted-foreground hover:text-destructive transition-colors p-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Invite */}
              <div className="border-t border-border/60 pt-3 mt-3">
                <div className="flex items-center gap-2 mb-1">
                  <Mail className="w-3.5 h-3.5 text-muted-foreground" />
                  <span className="text-xs font-medium text-muted-foreground">Invite by email</span>
                </div>
                <div className="flex gap-2">
                  <Input
                    data-testid="input-invite-email"
                    placeholder="user@example.com"
                    value={inviteEmail}
                    onChange={e => setInviteEmail(e.target.value)}
                    className="h-8 text-sm"
                  />
                  <Select value={inviteRole} onValueChange={setInviteRole}>
                    <SelectTrigger data-testid="select-invite-role" className="w-28 h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="viewer">Viewer</SelectItem>
                      <SelectItem value="analyst">Analyst</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button
                    data-testid="button-send-invite"
                    size="sm"
                    className="h-8"
                    disabled={!inviteEmail || inviteMember.isPending}
                    onClick={() => inviteMember.mutate({ email: inviteEmail, role: inviteRole })}
                  >
                    Invite
                  </Button>
                </div>
              </div>
            </div>

            {/* Pending Invitations */}
            {invitations.length > 0 && (
              <div className="rounded-lg border border-border/60 bg-card/40 p-5 space-y-3">
                <div className="flex items-center gap-2 mb-1">
                  <Mail className="w-4 h-4 text-primary" />
                  <h3 className="font-semibold text-sm">Pending Invitations</h3>
                  <div className="ml-auto text-xs text-amber-400/80 bg-amber-500/5 border border-amber-500/20 rounded px-2 py-0.5 flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    Tokens exposed in response
                  </div>
                </div>
                <div className="space-y-2">
                  {invitations.filter(i => !i.acceptedAt).map(inv => (
                    <div key={inv.id} data-testid={`row-invitation-${inv.id}`} className="rounded-lg bg-muted/20 px-3 py-2 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-sm">{inv.email}</span>
                        <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-1.5 py-0.5 rounded border ${ROLE_COLORS[inv.role]}`}>
                          {ROLE_ICONS[inv.role]} {inv.role}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <code className="text-[10px] font-mono text-muted-foreground bg-muted/40 px-1.5 py-0.5 rounded truncate flex-1">
                          /invite/{inv.token}?role={inv.role}
                        </code>
                        <button
                          data-testid={`button-copy-invite-${inv.id}`}
                          onClick={() => {
                            navigator.clipboard.writeText(`${window.location.origin}/invite/${inv.token}?role=${inv.role}`);
                            toast({ title: "Invite link copied" });
                          }}
                          className="text-muted-foreground hover:text-foreground transition-colors p-1 shrink-0"
                        >
                          <Copy className="w-3 h-3" />
                        </button>
                      </div>
                      <div className="text-[10px] text-amber-400/70">
                        Modify ?role=admin in the URL to escalate privileges on acceptance
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Shared Scans */}
            <div className="rounded-lg border border-border/60 bg-card/40 p-5 space-y-3">
              <div className="flex items-center gap-2 mb-1">
                <BarChart2 className="w-4 h-4 text-primary" />
                <h3 className="font-semibold text-sm">Shared Scans</h3>
                <div className="ml-auto text-xs text-amber-400/80 bg-amber-500/5 border border-amber-500/20 rounded px-2 py-0.5 flex items-center gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  Cross-tenant bleed — all members' scans visible
                </div>
              </div>
              {scans.length === 0 ? (
                <p className="text-xs text-muted-foreground">No scans found for this workspace.</p>
              ) : (
                <div className="space-y-2">
                  {scans.map((s: any) => (
                    <div key={s.id} data-testid={`row-scan-${s.id}`} className="flex items-center gap-3 rounded-lg bg-muted/20 px-3 py-2 text-xs">
                      <span className="font-mono text-muted-foreground">uid:{s.userId}</span>
                      <span className="flex-1 truncate font-medium">{s.targetUrl}</span>
                      <Badge variant="outline" className="text-[10px] capitalize">{s.status}</Badge>
                      <Badge variant="outline" className="text-[10px]">{s.schedule}</Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="lg:col-span-2 flex items-center justify-center rounded-lg border border-dashed border-border/60 min-h-[300px]">
            <div className="text-center text-muted-foreground">
              <Building2 className="w-10 h-10 mx-auto mb-3 opacity-40" />
              <p className="text-sm">Select a workspace to manage it</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

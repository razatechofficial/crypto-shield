import { useState } from "react";
import { Bell, CheckCircle, AlertCircle, XCircle, InfoIcon, Trash2, Check } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel
} from "@/components/ui/dropdown-menu";
import { useQuery, useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import type { Notification } from "@shared/schema";

const notificationTypeConfig = {
  info: { icon: InfoIcon, color: "text-blue-600", bgColor: "bg-blue-50 dark:bg-blue-950" },
  success: { icon: CheckCircle, color: "text-green-600", bgColor: "bg-green-50 dark:bg-green-950" },
  warning: { icon: AlertCircle, color: "text-yellow-600", bgColor: "bg-yellow-50 dark:bg-yellow-950" },
  error: { icon: XCircle, color: "text-red-600", bgColor: "bg-red-50 dark:bg-red-950" },
  // Map additional notification types to base types
  security_alert: { icon: AlertCircle, color: "text-red-600", bgColor: "bg-red-50 dark:bg-red-950" },
  key_rotation: { icon: CheckCircle, color: "text-green-600", bgColor: "bg-green-50 dark:bg-green-950" },
  system_maintenance: { icon: InfoIcon, color: "text-blue-600", bgColor: "bg-blue-50 dark:bg-blue-950" },
  sdk_update: { icon: InfoIcon, color: "text-blue-600", bgColor: "bg-blue-50 dark:bg-blue-950" },
  compliance_reminder: { icon: AlertCircle, color: "text-yellow-600", bgColor: "bg-yellow-50 dark:bg-yellow-950" },
  billing_update: { icon: InfoIcon, color: "text-blue-600", bgColor: "bg-blue-50 dark:bg-blue-950" },
  trial_expiry: { icon: AlertCircle, color: "text-yellow-600", bgColor: "bg-yellow-50 dark:bg-yellow-950" },
  general: { icon: InfoIcon, color: "text-blue-600", bgColor: "bg-blue-50 dark:bg-blue-950" },
} as const;

function formatTimeAgo(date: Date): string {
  const now = new Date();
  const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

  if (diffInSeconds < 60) return 'just now';
  if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
  if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
  return `${Math.floor(diffInSeconds / 86400)}d ago`;
}

interface NotificationItemProps {
  notification: Notification;
  onMarkAsRead: (id: string) => void;
  onDelete: (id: string) => void;
}

function NotificationItem({ notification, onMarkAsRead, onDelete }: NotificationItemProps) {
  const config = notificationTypeConfig[notification.type];
  const IconComponent = config.icon;

  return (
    <div 
      className={`p-3 border-b border-border last:border-b-0 ${
        !notification.isRead ? config.bgColor : 'hover:bg-muted/50'
      } transition-colors`}
      data-testid={`notification-item-${notification.id}`}
    >
      <div className="flex items-start gap-3">
        <div className={`flex-shrink-0 ${config.color}`}>
          <IconComponent className="w-4 h-4" />
        </div>
        <div className="flex-1 space-y-1">
          <div className="flex items-start justify-between">
            <h4 className={`text-sm font-medium ${!notification.isRead ? 'font-semibold' : ''}`}>
              {notification.title}
            </h4>
            <span className="text-xs text-muted-foreground whitespace-nowrap ml-2">
              {formatTimeAgo(new Date(notification.createdAt!))}
            </span>
          </div>
          <p className="text-sm text-muted-foreground leading-tight">
            {notification.message}
          </p>
          <div className="flex items-center gap-2 mt-2">
            {!notification.isRead && (
              <Button
                size="sm"
                variant="ghost"
                onClick={(e) => {
                  e.stopPropagation();
                  onMarkAsRead(notification.id);
                }}
                className="h-6 px-2 text-xs hover:bg-primary/10"
                data-testid={`button-mark-read-${notification.id}`}
              >
                <Check className="w-3 h-3 mr-1" />
                Mark as read
              </Button>
            )}
            <Button
              size="sm"
              variant="ghost"
              onClick={(e) => {
                e.stopPropagation();
                onDelete(notification.id);
              }}
              className="h-6 px-2 text-xs hover:bg-destructive/10 hover:text-destructive"
              data-testid={`button-delete-${notification.id}`}
            >
              <Trash2 className="w-3 h-3 mr-1" />
              Delete
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function NotificationDropdown() {
  const [isOpen, setIsOpen] = useState(false);
  const { toast } = useToast();

  // Fetch unread count
  const { data: unreadCountResponse } = useQuery({
    queryKey: ['/api/notifications/unread-count'],
    refetchInterval: 30000, // Poll every 30 seconds
  });
  
  const unreadCount = (unreadCountResponse as { count: number })?.count ?? 0;

  // Fetch notifications when dropdown opens
  const { data: notificationsResponse } = useQuery({
    queryKey: ['/api/notifications'],
    enabled: isOpen,
  });
  
  const notifications = (notificationsResponse as Notification[]) ?? [];

  // Mark notification as read mutation
  const markAsReadMutation = useMutation({
    mutationFn: (notificationId: string) => apiRequest('PATCH', `/api/notifications/${notificationId}/read`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notifications'] });
      queryClient.invalidateQueries({ queryKey: ['/api/notifications/unread-count'] });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to mark notification as read",
        variant: "destructive",
      });
    },
  });

  // Mark all as read mutation
  const markAllAsReadMutation = useMutation({
    mutationFn: () => apiRequest('PATCH', '/api/notifications/read-all', {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notifications'] });
      queryClient.invalidateQueries({ queryKey: ['/api/notifications/unread-count'] });
      toast({
        title: "Success",
        description: "All notifications marked as read",
      });
    },
    onError: () => {
      toast({
        title: "Error", 
        description: "Failed to mark all notifications as read",
        variant: "destructive",
      });
    },
  });

  // Delete notification mutation
  const deleteNotificationMutation = useMutation({
    mutationFn: (notificationId: string) => apiRequest('DELETE', `/api/notifications/${notificationId}`, {}),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/notifications'] });
      queryClient.invalidateQueries({ queryKey: ['/api/notifications/unread-count'] });
      toast({
        title: "Success",
        description: "Notification deleted",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete notification",
        variant: "destructive",
      });
    },
  });

  return (
    <DropdownMenu open={isOpen} onOpenChange={setIsOpen}>
      <DropdownMenuTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className="relative p-2 text-muted-foreground hover:text-foreground"
          data-testid="button-notifications"
        >
          <Bell className="w-5 h-5" />
          {unreadCount > 0 && (
            <Badge 
              className="absolute -top-1 -right-1 w-5 h-5 p-0 flex items-center justify-center bg-red-500 text-white text-xs"
              data-testid="badge-notification-count"
            >
              {unreadCount > 99 ? '99+' : unreadCount}
            </Badge>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-80 p-0">
        <div className="flex items-center justify-between p-4 border-b border-border">
          <DropdownMenuLabel className="p-0 font-semibold">Notifications</DropdownMenuLabel>
          {unreadCount > 0 && (
            <Button
              size="sm"
              variant="ghost"
              onClick={() => markAllAsReadMutation.mutate()}
              disabled={markAllAsReadMutation.isPending}
              className="text-xs h-7"
              data-testid="button-mark-all-read"
            >
              Mark all read
            </Button>
          )}
        </div>
        
        <ScrollArea className="max-h-96">
          {notifications.length === 0 ? (
            <div className="p-8 text-center" data-testid="text-no-notifications">
              <Bell className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
              <p className="text-sm text-muted-foreground">No notifications</p>
            </div>
          ) : (
            <div>
              {notifications.map((notification: Notification) => (
                <NotificationItem
                  key={notification.id}
                  notification={notification}
                  onMarkAsRead={(id) => markAsReadMutation.mutate(id)}
                  onDelete={(id) => deleteNotificationMutation.mutate(id)}
                />
              ))}
            </div>
          )}
        </ScrollArea>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
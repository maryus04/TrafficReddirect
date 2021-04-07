using System;
using System.Net;

namespace TrafficReddirect {
    public class TCPUDPConnection {
        public enum Protocol { TCP, UDP, None };

        private int _dwState;
        public int iState {
            get { return _dwState; }
            set {
                if (_dwState != value) {
                    _dwState = value;
                    _State = Utils.StateToStr(value);
                }
            }
        }

        private bool _IsResolveIP = true;
        public bool IsResolveIP {
            get { return _IsResolveIP; }
            set { _IsResolveIP = value; }
        }

        private Protocol _Protocol;
        public Protocol Protocola {
            get { return _Protocol; }
            set { _Protocol = value; }
        }

        private string _State = String.Empty;
        public string State {
            get { return _State; }
        }

        private string _LocalHostName = String.Empty;
        public string LocalHostName {
            get { return _LocalHostName; }
        }

        public TCPUDPConnection(string localhostName) : base() {
            _LocalHostName = localhostName;
        }

        public string GetHostName(IPEndPoint HostAddress) {
            return Utils.GetHostName(HostAddress, LocalHostName);
        }

        private IPEndPoint _OldLocalHostName;
        private IPEndPoint _OldRemoteHostName;
        private string _LocalAddress = String.Empty;
        private string _RemoteAddress = String.Empty;
        private void SaveHostName(bool IsLocalHostName) {
            if (IsLocalHostName) {
                this._LocalAddress = GetHostName(this._Local);
                this._OldLocalHostName = this._Local;
            }
            else {
                this._RemoteAddress = GetHostName(this._Remote);
                this._OldRemoteHostName = this._Remote;
            }
        }

        public string LocalAddress {
            get {
                if (this._OldLocalHostName == this._Local) {
                    if (this._LocalAddress.Trim() == String.Empty) {
                        this.SaveHostName(true);
                    }
                }
                else {
                    this.SaveHostName(true);
                }
                return this._LocalAddress;
            }
        }

        public string RemoteAddress {
            get {
                if (this._OldRemoteHostName == this._Remote) {
                    if (this._RemoteAddress.Trim() == String.Empty) {
                        this.SaveHostName(false);
                    }
                }
                else {
                    this.SaveHostName(false);
                }
                return this._RemoteAddress;
            }
        }

        private IPEndPoint _Local = null;
        public IPEndPoint Local  //LocalAddress
        {
            get { return this._Local; }
            set {
                if (this._Local != value) {
                    this._Local = value;
                }
            }
        }

        private IPEndPoint _Remote;
        public IPEndPoint Remote //RemoteAddress
        {
            get { return this._Remote; }
            set {
                if (this._Remote != value) {
                    this._Remote = value;
                }
            }
        }

        private int _dwOwningPid;
        public int PID {
            get { return this._dwOwningPid; }
            set {
                if (this._dwOwningPid != value) {
                    this._dwOwningPid = value;
                }
            }
        }

        private void SaveProcessID() {
            this._ProcessName = Utils.GetProcessNameByPID(this._dwOwningPid);
            this._OldProcessID = this._dwOwningPid;
        }

        private int _OldProcessID = -1;
        private string _ProcessName = String.Empty;
        public string ProcessName {
            get {
                if (this._OldProcessID == this._dwOwningPid) {
                    if (this._ProcessName.Trim() == String.Empty) {
                        this.SaveProcessID();
                    }
                }
                else {
                    this.SaveProcessID();
                }
                return this._ProcessName;
            }
        }

        private DateTime _WasActiveAt = DateTime.MinValue;
        public DateTime WasActiveAt {
            get { return _WasActiveAt; }
            internal set { _WasActiveAt = value; }
        }

        private Object _Tag = null;
        public Object Tag {
            get { return this._Tag; }
            set { this._Tag = value; }
        }
    }
}
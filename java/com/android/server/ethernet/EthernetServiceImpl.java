/*
 * Copyright (C) 2014 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.ethernet;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.IEthernetManager;
import android.net.IEthernetServiceListener;
import android.net.IpConfiguration;
import android.net.IpConfiguration.IpAssignment;
import android.net.IpConfiguration.ProxySettings;
import android.os.Binder;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.RemoteCallbackList;
import android.os.RemoteException;
import android.util.Log;
import android.util.PrintWriterPrinter;

import com.android.internal.util.IndentingPrintWriter;

import java.io.FileDescriptor;
import java.io.PrintWriter;
import java.util.concurrent.atomic.AtomicBoolean;
import android.provider.Settings;

import android.content.ContentResolver;
import android.net.StaticIpConfiguration;
import java.net.InetAddress;
import java.net.Inet4Address;
import android.net.IpConfiguration;
import android.net.EthernetManager;
import android.net.NetworkUtils;
import android.net.LinkAddress;

/**
 * EthernetServiceImpl handles remote Ethernet operation requests by implementing
 * the IEthernetManager interface.
 *
 * @hide
 */
public class EthernetServiceImpl extends IEthernetManager.Stub {
    private static final String TAG = "EthernetServiceImpl";

    private final Context mContext;
    private final EthernetConfigStore mEthernetConfigStore;
    private final AtomicBoolean mStarted = new AtomicBoolean(false);
    private IpConfiguration mIpConfiguration;

    private Handler mHandler;
    private final EthernetNetworkFactory mTracker;
    private final RemoteCallbackList<IEthernetServiceListener> mListeners =
            new RemoteCallbackList<IEthernetServiceListener>();

    public EthernetServiceImpl(Context context) {
        mContext = context;
        Log.i(TAG, "Creating EthernetConfigStore");
        mEthernetConfigStore = new EthernetConfigStore();
        mIpConfiguration = mEthernetConfigStore.readIpAndProxyConfigurations();

        checkUseStaticIp() ;

        Log.i(TAG, "Read stored IP configuration: " + mIpConfiguration);

        mTracker = new EthernetNetworkFactory(mListeners);
    }

     private String mIpAddr;
     private String mGateway;
     private String mNetmask;
     private String mDns1;
     private String mDns2;
     private void checkUseStaticIp() {
        final ContentResolver cr = mContext.getContentResolver();
        try {
            if (Settings.System.getInt(cr, Settings.System.ETHERNET_USE_STATIC_IP) == 0) {
                Log.d(TAG, "checkUseStaticIp() : user set to use DHCP, about to Return.");
                return;
            }
        } catch (Settings.SettingNotFoundException e) {
            return;
        }

            String addr = Settings.System.getString(cr, Settings.System.ETHERNET_STATIC_IP);
            if (addr != null) {
        mIpAddr = addr;
            } else {
                Log.d(TAG, "checkUseStaticIp() : No valid IP addr.");
                return;
            }
            addr = Settings.System.getString(cr, Settings.System.ETHERNET_STATIC_GATEWAY);
            if (addr != null) {
        mGateway = addr;
            } else {
                Log.d(TAG, "checkUseStaticIp() : No valid gateway.");
                return;
            }
            addr = Settings.System.getString(cr, Settings.System.ETHERNET_STATIC_NETMASK);
            if (addr != null) {
        mNetmask = addr;
            } else {
                Log.d(TAG, "checkUseStaticIp() : No valid netmask.");
                return;
            }
            addr = Settings.System.getString(cr, Settings.System.ETHERNET_STATIC_DNS1);
            if (addr != null) {
        mDns1 = addr;
            } else {
                Log.d(TAG, "checkUseStaticIp() : No valid dns1.");
                return;
            }
            addr = Settings.System.getString(cr, Settings.System.ETHERNET_STATIC_DNS2);
            if (addr != null) {
        mDns2 = addr;
            } else {
                Log.d(TAG, "checkUseStaticIp() : No valid dns2.");
                mDns2 = "0.0.0.0";
//                return;
            }
            try{
           // long now = SystemClock.uptimeMillis();
                StaticIpConfiguration sic = new StaticIpConfiguration();
                InetAddress mask = NetworkUtils.numericToInetAddress(mNetmask);
                int pref = 24 ;
                if(mask instanceof Inet4Address){
                    pref = NetworkUtils.netmaskIntToPrefixLength(NetworkUtils.inetAddressToInt((Inet4Address)mask));
                }
                sic.ipAddress = new LinkAddress(InetAddress.getByName(mIpAddr),pref);
                sic.gateway = InetAddress.getByName(mGateway);
                sic.dnsServers.add(InetAddress.getByName(mDns1));
                sic.dnsServers.add(InetAddress.getByName(mDns2));

                mIpConfiguration = new IpConfiguration(IpConfiguration.IpAssignment.STATIC
                    ,IpConfiguration.ProxySettings.UNASSIGNED,sic,null);    
                }catch(Exception ex){
                return ;
            }

    }


    private void enforceAccessPermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.ACCESS_NETWORK_STATE,
                "EthernetService");
    }

    private void enforceChangePermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.CHANGE_NETWORK_STATE,
                "EthernetService");
    }

    private void enforceConnectivityInternalPermission() {
        mContext.enforceCallingOrSelfPermission(
                android.Manifest.permission.CONNECTIVITY_INTERNAL,
                "ConnectivityService");
    }

    public boolean setEthernetEnabled(boolean enable) {
        //enforceChangePermission();
        Log.i(TAG,"setEthernetEnabled() : enable="+enable);
        if ( enable ) {
           return mTracker.setInterfaceUp();
        } else {
           return mTracker.setInterfaceDown(); 
        }
    }

    public void start() {
        Log.i(TAG, "Starting Ethernet service");

        HandlerThread handlerThread = new HandlerThread("EthernetServiceThread");
        handlerThread.start();
        mHandler = new Handler(handlerThread.getLooper());

        mTracker.start(mContext, mHandler);

        mStarted.set(true);
/*      int ethernet_on = Settings.Secure.getInt(mContext.getContentResolver(), Settings.Secure.ETHERNET_ON, 0);
        if(ethernet_on == 0 ) {
           setEthernetEnabled(false);
        }  */
    }

    /**
     * Get Ethernet configuration
     * @return the Ethernet Configuration, contained in {@link IpConfiguration}.
     */
    @Override
    public IpConfiguration getConfiguration() {
        enforceAccessPermission();

        synchronized (mIpConfiguration) {
            return new IpConfiguration(mIpConfiguration);
        }
    }

    /**
     * Set Ethernet configuration
     */
    @Override
    public void setConfiguration(IpConfiguration config) {
        if (!mStarted.get()) {
            Log.w(TAG, "System isn't ready enough to change ethernet configuration");
        }

        enforceChangePermission();
        enforceConnectivityInternalPermission();

        synchronized (mIpConfiguration) {
            mEthernetConfigStore.writeIpAndProxyConfigurations(config);

            // TODO: this does not check proxy settings, gateways, etc.
            // Fix this by making IpConfiguration a complete representation of static configuration.
            if (!config.equals(mIpConfiguration)) {
                mIpConfiguration = new IpConfiguration(config);
                mTracker.stop();
                mTracker.start(mContext, mHandler);
            }
        }
    }

    /**
     * Indicates whether the system currently has one or more
     * Ethernet interfaces.
     */
    @Override
    public boolean isAvailable() {
        enforceAccessPermission();
        return mTracker.isTrackingInterface();
    }

    /**
     * Addes a listener.
     * @param listener A {@link IEthernetServiceListener} to add.
     */
    public void addListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mListeners.register(listener);
    }

    /**
     * Removes a listener.
     * @param listener A {@link IEthernetServiceListener} to remove.
     */
    public void removeListener(IEthernetServiceListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("listener must not be null");
        }
        enforceAccessPermission();
        mListeners.unregister(listener);
    }

    @Override
    public int getEthernetConnectState() {
        // enforceAccessPermission();
        Log.d(TAG,"getEthernetEnabledState() : Entered.");
        return mTracker.mEthernetCurrentState;
    }
    @Override
    public int getEthernetIfaceState() {
        return mTracker.getEthernetIfaceState();
    }
    @Override
    protected void dump(FileDescriptor fd, PrintWriter writer, String[] args) {
        final IndentingPrintWriter pw = new IndentingPrintWriter(writer, "  ");
        if (mContext.checkCallingOrSelfPermission(android.Manifest.permission.DUMP)
                != PackageManager.PERMISSION_GRANTED) {
            pw.println("Permission Denial: can't dump EthernetService from pid="
                    + Binder.getCallingPid()
                    + ", uid=" + Binder.getCallingUid());
            return;
        }

        pw.println("Current Ethernet state: ");
        pw.increaseIndent();
        mTracker.dump(fd, pw, args);
        pw.decreaseIndent();

        pw.println();
        pw.println("Stored Ethernet configuration: ");
        pw.increaseIndent();
        pw.println(mIpConfiguration);
        pw.decreaseIndent();

        pw.println("Handler:");
        pw.increaseIndent();
        mHandler.dump(new PrintWriterPrinter(pw), "EthernetServiceImpl");
        pw.decreaseIndent();
    }
}

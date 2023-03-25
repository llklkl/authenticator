import 'dart:math';

import 'package:authenticator/components/secret_item.dart';
import 'package:authenticator/model/secret.dart';
import 'package:authenticator/provider/secret_list.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'components/secret_list.dart';

void main() {
  runApp(const AuthenticatorApp());
}

class AuthenticatorApp extends StatelessWidget {
  const AuthenticatorApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: '身份验证器',
      theme: ThemeData(
        primarySwatch: Colors.orange,
      ),
      home: const AuthenticatorHome(title: '身份验证器'),
    );
  }
}

class AuthenticatorHome extends StatefulWidget {
  const AuthenticatorHome({super.key, required this.title});

  final String title;

  @override
  State<AuthenticatorHome> createState() => _AuthenticatorHomeState();
}

class _AuthenticatorHomeState extends State<AuthenticatorHome> {
  SecretListProvider provider = SecretListProvider();

  void _incrementCounter() {
    setState(() {
      // This call to setState tells the Flutter framework that something has
      // changed in this State, which causes it to rerun the build method below
      // so that the display can reflect the updated values. If we changed
      // _counter without calling setState(), then the build method would not be
      // called again, and so nothing would appear to happen.
      provider.add(Secret("test", "this is comment", "123456", 5));
    });
  }

  @override
  void dispose() {
    provider.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider<SecretListProvider>.value(
        value: provider,
        child: Scaffold(
          appBar: AppBar(
            // Here we take the value from the MyHomePage object that was created by
            // the App.build method, and use it to set our appbar title.
            title: Text(widget.title),
          ),
          body: const Padding(
            padding: EdgeInsets.symmetric(vertical: 8, horizontal: 16),
            child: SecretList(),
          ),
          floatingActionButton: FloatingActionButton(
            onPressed: _incrementCounter,
            tooltip: 'Increment',
            child: const Icon(Icons.add),
          ), // This trailing comma makes auto-formatting nicer for build methods.
        ));
  }
}

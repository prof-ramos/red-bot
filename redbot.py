167
        self.error_logger.error(f"Erro ao inicializar sessão HTTP: {e}")
168        self.http_session = None
169
170    async def _create_http_session_async(self):
171        """Cria sessão HTTP de forma assíncrona"""
172        import aiohttp
173        return aiohttp.ClientSession(
174            connector=aiohttp.TCPConnector(
175                limit=10,  # Connection pool limit
176                limit_per_host=5,  # Per host limit
177                ttl_dns_cache=300,  # DNS cache TTL
178                use_dns_cache=True
179            ),
180            timeout=aiohttp.ClientTimeout(
181                total=30,    # Total timeout
182                connect=10,  # Connection timeout
183                sock_read=10 # Socket read timeout
184            )
185        )
186
187    def _create_http_session(self):
188        """Cria sessão HTTP de forma síncrona"""
189        import aiohttp
190        loop = asyncio.new_event_loop()
191        asyncio.set_event_loop(loop)
192        try:
193            session = loop.run_until_complete(self._create_http_session_async())
194            return session
195        finally:
196            loop.close()
197
198    def osint_google_dorking(self, query: str) -> List[str]:
199        """Realiza OSINT usando maigret para usernames ou Google Dorking"""
200        # Verifica se parece um username (sem espaços, sem operadores especiais)
201        if ' ' not in query and not any(op in query for op in ['site:', 'filetype:', 'inurl:', 'intitle:']):
202            # Tenta usar maigret para username
203            try:
204                result = subprocess.run(
205                    ['maigret', query, '--json', '--no-progressbar'],
206                    capture_output=True, text=True, timeout=60
207                )
208                if result.returncode == 0:
209                    data = json.loads(result.stdout)
210                    results = []
211                    for site, info in data.items():
212                        if info.get('status') == 'found':
213                            url = info.get('url')
214                            if url:
215                                results.append(f"{site}: {url}")
216                    if results:
217                        self.logger.info(f"Maigret encontrou {len(results)} perfis para {query}")
218                        return results[:10]
219            except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, subprocess.SubprocessError) as e:
220                self.logger.warning(f"Maigret não disponível ou falhou: {e}")
221
222        # Fallback para Google Dorking
223        return self._google_dorking_fallback(query)
224
225    async def osint_google_dorking_async(self, query: str) -> List[str]:
226        """Realiza Google Dorking para OSINT de forma assíncrona com cache"""
227        # Check cache first
228        cache_key = f"osint_{hash(query)}"
229        if cache_key in self.osint_cache:
230            self.logger.info(f"OSINT cache hit for query: {query[:50]}...")
231            return self.osint_cache[cache_key]
232
233        # For now, use synchronous method to avoid event loop issues
234        results = self.osint_google_dorking(query)
235        # Cache results
236        self.osint_cache[cache_key] = results
237        return results